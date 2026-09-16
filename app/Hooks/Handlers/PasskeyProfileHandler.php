<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Ceremony;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\RelyingParty;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * Registering and removing passkeys, on the WordPress profile screen.
 *
 * The same asymmetry the authenticator app uses, and for the same reason: a user may
 * only add a passkey to their own account, while an administrator may remove one from
 * anybody's. Adding is a thing only the person holding the device can meaningfully do -
 * and an administrator who could add one would be adding their own device to someone
 * else's account, which is not recovery, it is a back door.
 */
class PasskeyProfileHandler
{
    const NONCE_ACTION = 'fls_passkey_profile';

    /**
     * The outstanding registration challenge.
     *
     * A transient rather than the pending login row, because this ceremony happens
     * inside an existing session rather than during a login. Short lived: a challenge
     * that outlives the page it was drawn for is one an attacker has had time to work
     * with.
     */
    const CHALLENGE_TRANSIENT = 'fls_passkey_challenge_';

    const CHALLENGE_TTL = 300;

    public function register()
    {
        add_action('show_user_profile', [$this, 'renderSection']);
        add_action('edit_user_profile', [$this, 'renderSection']);

        add_action('wp_ajax_fluent_auth_passkey_options', [$this, 'handleOptions']);
        add_action('wp_ajax_fluent_auth_passkey_register', [$this, 'handleRegister']);
        add_action('wp_ajax_fluent_auth_passkey_delete', [$this, 'handleDelete']);
        add_action('wp_ajax_fluent_auth_passkey_rename', [$this, 'handleRename']);

        // Nothing should outlive the account it belonged to.
        add_action('deleted_user', [$this, 'purgeForUser']);
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    public function renderSection($user)
    {
        if (!$user instanceof \WP_User || !current_user_can('edit_user', $user->ID)) {
            return;
        }

        if (!PasskeyTwoFaMethod::isAllowedForUser($user) && !PasskeyTwoFaMethod::isEnrolled($user)) {
            return;
        }

        $isSelf = get_current_user_id() === (int)$user->ID;
        $credentials = PasskeyStore::getForUser($user);

        ?>
        <h2 id="fls-passkeys"><?php esc_html_e('Passkeys', 'fluent-security'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e('Registered passkeys', 'fluent-security'); ?></th>
                <td>
                    <?php
                    wp_nonce_field(self::NONCE_ACTION, '_fls_passkey_nonce');

                    if (!RelyingParty::isSupported()) {
                        echo '<p class="description">'
                            . esc_html__('Passkeys need the site to be served over https. They cannot be set up here.', 'fluent-security')
                            . '</p>';
                        echo '</td></tr></table>';
                        return;
                    }

                    $this->renderList($credentials, $isSelf);

                    if ($isSelf) {
                        $this->renderFallbackNotice($user, $credentials);
                        $this->renderRecoveryCodes($user, $credentials);
                        $this->renderAddForm($user);
                    } elseif (!$credentials) {
                        echo '<p class="description">' . esc_html__('This user has not registered a passkey.', 'fluent-security') . '</p>';
                    }
                    ?>
                </td>
            </tr>
        </table>
        <?php

        if ($isSelf) {
            $this->renderScript();
        }
    }

    /**
     * The account's recovery codes, for somebody whose only factor is a passkey.
     *
     * Rendered here only when the authenticator app section is not already offering it,
     * so the profile never shows the same control twice. The checkbox is the app
     * section's own field name on purpose: the profile screen is one form, and
     * TotpProfileHandler::handleUpdate() is what reads it.
     *
     * It exists because a passkey has no code to fall back on. PasskeyTwoFaMethod counts
     * these codes as the fallback that lets a single credential stand alone, so somebody
     * holding one passkey and a set of codes they cannot replace is one lost laptop from
     * being locked out of an account the site believes is recoverable.
     *
     * @param $user \WP_User
     * @param $credentials array
     * @return void
     */
    private function renderRecoveryCodes($user, $credentials)
    {
        if (!$credentials || TotpTwoFaMethod::isEnrolled($user)) {
            return;
        }

        $remaining = RecoveryCodes::countRemaining($user);

        ?>
        <p class="description" style="margin: 16px 0 8px;">
            <?php
            /* translators: %d: number of unused recovery codes */
            echo esc_html(sprintf(_n('%d unused recovery code remaining.', '%d unused recovery codes remaining.', $remaining, 'fluent-security'), $remaining));
            ?>
        </p>
        <?php if ($remaining < 3) : ?>
            <p class="description" style="color:#b32d2e;margin-bottom: 8px;">
                <?php esc_html_e('You are running low. Generate a new set and store them somewhere other than the device holding your passkey.', 'fluent-security'); ?>
            </p>
        <?php endif; ?>
        <p>
            <label>
                <input type="checkbox" name="fls_totp_regenerate_recovery" value="yes"/>
                <?php esc_html_e('Generate a new set of recovery codes (this invalidates the old ones)', 'fluent-security'); ?>
            </label>
        </p>
        <?php
    }

    /**
     * @param $credentials array
     * @param $isSelf bool
     * @return void
     */
    private function renderList($credentials, $isSelf)
    {
        if (!$credentials) {
            return;
        }

        ?>
        <table class="widefat striped" style="max-width: 640px;margin-bottom: 16px;">
            <thead>
            <tr>
                <th><?php esc_html_e('Name', 'fluent-security'); ?></th>
                <th><?php esc_html_e('Added', 'fluent-security'); ?></th>
                <th><?php esc_html_e('Last used', 'fluent-security'); ?></th>
                <th></th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($credentials as $credential) : ?>
                <tr>
                    <td>
                        <strong><?php echo esc_html($credential->label); ?></strong>
                        <?php if ($credential->backup_eligible) : ?>
                            <br/><span class="description" style="font-size:11px;">
                                <?php esc_html_e('Synced across your devices', 'fluent-security'); ?>
                            </span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($credential->created_at ? mysql2date(get_option('date_format'), $credential->created_at) : '—'); ?></td>
                    <td><?php echo esc_html($credential->last_used_at ? mysql2date(get_option('date_format'), $credential->last_used_at) : __('Never', 'fluent-security')); ?></td>
                    <td style="text-align:right;">
                        <button type="button" class="button button-small fls-passkey-remove"
                                data-id="<?php echo esc_attr($credential->id); ?>">
                            <?php esc_html_e('Remove', 'fluent-security'); ?>
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    /**
     * Says out loud when a passkey is registered but will not actually be asked for.
     *
     * Without this the feature fails silently in the one way a user cannot diagnose:
     * they register a device, see it listed, and are then never challenged with it,
     * because a single passkey with nothing behind it is a lockout waiting for the day
     * the device is lost. See PasskeyTwoFaMethod::hasFallback().
     *
     * @param $user \WP_User
     * @param $credentials array
     * @return void
     */
    private function renderFallbackNotice($user, $credentials)
    {
        if (!$credentials || PasskeyTwoFaMethod::hasFallback($user)) {
            return;
        }

        ?>
        <div style="border-left: 4px solid #dba617;background:#fff;padding: 10px 14px;margin: 0 0 16px;max-width:640px;box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <p style="margin: 0;">
                <strong><?php esc_html_e('Not in use yet.', 'fluent-security'); ?></strong>
                <?php
                if (TotpTwoFaMethod::isAllowedForUser($user)) {
                    esc_html_e('Register a second passkey, or set up an authenticator app, and this one will start being asked for at login. One passkey on its own would lock you out of the account if you lost the device.', 'fluent-security');
                } else {
                    esc_html_e('Register a second passkey and they will start being asked for at login. One on its own would lock you out of the account if you lost the device.', 'fluent-security');
                }
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    private function renderAddForm($user)
    {
        if (!PasskeyTwoFaMethod::isAllowedForUser($user)) {
            return;
        }

        ?>
        <p>
            <label for="fls_passkey_label"><?php esc_html_e('Name this device', 'fluent-security'); ?></label><br/>
            <input type="text" id="fls_passkey_label" class="regular-text"
                   placeholder="<?php esc_attr_e('Work laptop', 'fluent-security'); ?>"/>
        </p>
        <p>
            <button type="button" class="button button-primary" id="fls_passkey_add">
                <?php esc_html_e('Add a passkey', 'fluent-security'); ?>
            </button>
            <span id="fls_passkey_status" style="margin-left: 10px;"></span>
        </p>
        <p class="description" style="max-width:640px;">
            <?php esc_html_e('You will be asked for your fingerprint, face or device PIN. Nothing about them ever reaches this site - only a public key it can check signatures against.', 'fluent-security'); ?>
        </p>
        <?php
    }

    /**
     * Hands the browser a fresh challenge to register against.
     *
     * @return void
     */
    public function handleOptions()
    {
        $user = $this->authorise(true);

        try {
            $challenge = Ceremony::createChallenge();
        } catch (WebAuthnException $e) {
            wp_send_json_error(['message' => __('This server cannot generate a secure challenge.', 'fluent-security')], 500);
        }

        set_transient(self::CHALLENGE_TRANSIENT . $user->ID, Base64Url::encode($challenge), self::CHALLENGE_TTL);

        $existing = [];

        foreach (PasskeyStore::getForUser($user) as $credential) {
            $existing[] = $credential->credential_id;
        }

        wp_send_json_success([
            'options' => Registration::getCreationOptions($user, $challenge, $existing)
        ]);
    }

    /**
     * @return void
     */
    public function handleRegister()
    {
        $user = $this->authorise(true);

        $stored = get_transient(self::CHALLENGE_TRANSIENT . $user->ID);
        $challenge = is_string($stored) ? Base64Url::decode($stored) : false;

        /*
         * Spent on sight, before the response is looked at. A challenge that survives a
         * failed attempt is a challenge that can be attempted repeatedly.
         */
        delete_transient(self::CHALLENGE_TRANSIENT . $user->ID);

        if ($challenge === false) {
            wp_send_json_error(['message' => __('That took too long. Please try again.', 'fluent-security')], 400);
        }

        $raw = Arr::get($_POST, 'response');
        $response = is_string($raw) ? json_decode(wp_unslash($raw), true) : null;

        if (!is_array($response)) {
            wp_send_json_error(['message' => __('The passkey response could not be read.', 'fluent-security')], 400);
        }

        try {
            $verified = Registration::verify($response, $challenge);
        } catch (WebAuthnException $e) {
            do_action('fluent_auth/passkey_registration_failed', $user, $e->getMessage());

            wp_send_json_error(['message' => __('That passkey could not be verified. Please try again.', 'fluent-security')], 400);
        }

        $transports = Arr::get($_POST, 'transports');
        $transports = is_string($transports) ? json_decode(wp_unslash($transports), true) : [];

        $added = PasskeyStore::add($user, $verified, Arr::get($_POST, 'label'), (array)$transports);

        if (is_wp_error($added)) {
            wp_send_json_error(['message' => $added->get_error_message()], 400);
        }

        wp_send_json_success([
            'message' => __('Passkey registered.', 'fluent-security')
        ]);
    }

    /**
     * @return void
     */
    public function handleDelete()
    {
        // Not self-only: removing a credential is how an administrator rescues an account.
        $user = $this->authorise(false);

        $id = (int)Arr::get($_POST, 'id');

        if (!PasskeyStore::delete($id, $user)) {
            wp_send_json_error(['message' => __('That passkey could not be removed.', 'fluent-security')], 400);
        }

        wp_send_json_success(['message' => __('Passkey removed.', 'fluent-security')]);
    }

    /**
     * @return void
     */
    public function handleRename()
    {
        $user = $this->authorise(false);

        $id = (int)Arr::get($_POST, 'id');

        if (!PasskeyStore::rename($id, $user, Arr::get($_POST, 'label'))) {
            wp_send_json_error(['message' => __('That passkey could not be renamed.', 'fluent-security')], 400);
        }

        wp_send_json_success(['message' => __('Passkey renamed.', 'fluent-security')]);
    }

    /**
     * @param $userId int
     * @return void
     */
    public function purgeForUser($userId)
    {
        PasskeyStore::deleteAllForUser($userId);
    }

    /**
     * Checks the nonce and the capability, and answers who is being acted on.
     *
     * Exits rather than returning a failure, so no caller can proceed past a refused
     * request by forgetting to check.
     *
     * @param $selfOnly bool whether the action may only be taken on one's own account
     * @return \WP_User
     */
    private function authorise($selfOnly)
    {
        check_ajax_referer(self::NONCE_ACTION, '_fls_passkey_nonce');

        $userId = (int)Arr::get($_POST, 'user_id');
        $userId = $userId ? $userId : get_current_user_id();

        if (!current_user_can('edit_user', $userId)) {
            wp_send_json_error(['message' => __('You cannot change this account.', 'fluent-security')], 403);
        }

        /*
         * Registering for somebody else would mean adding a device they do not hold to
         * an account that is not yours, which is not a thing an administrator should be
         * able to do even with every capability there is.
         */
        if ($selfOnly && $userId !== get_current_user_id()) {
            wp_send_json_error(['message' => __('A passkey can only be added to your own account.', 'fluent-security')], 403);
        }

        $user = get_user_by('ID', $userId);

        if (!$user instanceof \WP_User) {
            wp_send_json_error(['message' => __('Unknown user.', 'fluent-security')], 404);
        }

        if ($selfOnly && !PasskeyTwoFaMethod::isAllowedForUser($user)) {
            wp_send_json_error(['message' => __('Passkeys are not enabled for this account.', 'fluent-security')], 403);
        }

        return $user;
    }

    /**
     * @return void
     */
    private function renderScript()
    {
        $strings = [
            'unsupported' => __('This browser cannot create passkeys.', 'fluent-security'),
            'prompting'   => __('Follow the prompt from your device…', 'fluent-security'),
            'saving'      => __('Saving…', 'fluent-security'),
            'cancelled'   => __('Cancelled.', 'fluent-security'),
            'confirm'     => __('Remove this passkey? If it is the only one you have, make sure you can still sign in another way.', 'fluent-security')
        ];

        ?>
        <script>
            (function () {
                var nonceField = document.getElementById('_fls_passkey_nonce');
                var addButton = document.getElementById('fls_passkey_add');
                var status = document.getElementById('fls_passkey_status');
                var strings = <?php echo wp_json_encode($strings); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
                var ajaxUrl = <?php echo wp_json_encode(admin_url('admin-ajax.php')); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
                var userId = <?php echo (int)get_current_user_id(); ?>;

                function toBuffer(value) {
                    var normalised = String(value).replace(/-/g, '+').replace(/_/g, '/');
                    var remainder = normalised.length % 4;

                    if (remainder) {
                        normalised += new Array(5 - remainder).join('=');
                    }

                    var binary = window.atob(normalised);
                    var bytes = new Uint8Array(binary.length);

                    for (var i = 0; i < binary.length; i++) {
                        bytes[i] = binary.charCodeAt(i);
                    }

                    return bytes;
                }

                function toBase64Url(buffer) {
                    var bytes = new Uint8Array(buffer);
                    var binary = '';

                    for (var i = 0; i < bytes.length; i++) {
                        binary += String.fromCharCode(bytes[i]);
                    }

                    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                }

                function post(action, payload) {
                    var body = new FormData();
                    body.append('action', action);
                    body.append('_fls_passkey_nonce', nonceField.value);
                    body.append('user_id', userId);

                    Object.keys(payload || {}).forEach(function (key) {
                        body.append(key, payload[key]);
                    });

                    return fetch(ajaxUrl, {method: 'POST', credentials: 'same-origin', body: body})
                        .then(function (response) {
                            return response.json();
                        })
                        .then(function (json) {
                            if (!json || !json.success) {
                                throw new Error((json && json.data && json.data.message) || 'Request failed');
                            }

                            return json.data;
                        });
                }

                function setStatus(text) {
                    if (status) {
                        status.textContent = text || '';
                    }
                }

                if (addButton) {
                    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
                        addButton.disabled = true;
                        setStatus(strings.unsupported);
                    } else {
                        addButton.addEventListener('click', function () {
                            addButton.disabled = true;
                            setStatus(strings.prompting);

                            var label = document.getElementById('fls_passkey_label');

                            post('fluent_auth_passkey_options', {}).then(function (data) {
                                var options = data.options;

                                options.challenge = toBuffer(options.challenge);
                                options.user.id = toBuffer(options.user.id);
                                options.excludeCredentials = (options.excludeCredentials || []).map(function (item) {
                                    item.id = toBuffer(item.id);
                                    return item;
                                });

                                return navigator.credentials.create({publicKey: options});
                            }).then(function (credential) {
                                setStatus(strings.saving);

                                var transports = credential.response.getTransports
                                    ? credential.response.getTransports()
                                    : [];

                                return post('fluent_auth_passkey_register', {
                                    label: label ? label.value : '',
                                    transports: JSON.stringify(transports || []),
                                    response: JSON.stringify({
                                        rawId: toBase64Url(credential.rawId),
                                        clientDataJSON: toBase64Url(credential.response.clientDataJSON),
                                        attestationObject: toBase64Url(credential.response.attestationObject)
                                    })
                                });
                            }).then(function () {
                                window.location.reload();
                            }).catch(function (error) {
                                addButton.disabled = false;
                                setStatus(error && error.message ? error.message : strings.cancelled);
                            });
                        });
                    }
                }

                Array.prototype.forEach.call(document.querySelectorAll('.fls-passkey-remove'), function (button) {
                    button.addEventListener('click', function () {
                        if (!window.confirm(strings.confirm)) {
                            return;
                        }

                        button.disabled = true;

                        post('fluent_auth_passkey_delete', {id: button.getAttribute('data-id')})
                            .then(function () {
                                window.location.reload();
                            })
                            .catch(function (error) {
                                button.disabled = false;
                                window.alert(error && error.message ? error.message : '');
                            });
                    });
                });
            })();
        </script>
        <?php
    }
}
