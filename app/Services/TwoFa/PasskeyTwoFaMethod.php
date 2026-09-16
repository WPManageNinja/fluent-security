<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\WebAuthn\Assertion;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Ceremony;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\RelyingParty;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * A passkey - Touch ID, Windows Hello, a password manager or a security key.
 *
 * Registered ahead of the authenticator app in TwoFaService, because where a user has
 * both this is the stronger one: the credential is bound to this site's domain by the
 * browser itself, so a user who is standing on a convincing copy of the login page
 * cannot complete it however carefully they are talked through it. A typed code has no
 * such protection - it is six digits that work wherever they are typed.
 *
 * Like the authenticator app it proves a device, so once enrolled it is asked for
 * however the user signed in. Unlike the authenticator app there is no code to fall
 * back on, which is why this method refuses to become the only thing standing in front
 * of an account: see isAvailableForUser().
 */
class PasskeyTwoFaMethod extends BaseTwoFaMethod
{
    /**
     * Where the outstanding challenge is kept between raising it and answering it.
     *
     * Reuses the pending row's existing column. What goes in it here is a nonce rather
     * than a hashed secret - it is public the moment the form renders and its whole job
     * is to be unrepeatable - so nothing is gained by hashing it, and the base64url of
     * 32 bytes is 43 characters against the column's 100.
     */
    const CHALLENGE_COLUMN = 'two_fa_code_hash';

    public function getKey()
    {
        return 'passkey';
    }

    public function getTitle()
    {
        return __('Passkey', 'fluent-security');
    }

    public function getSatisfiedFactor()
    {
        return AuthFactor::DEVICE;
    }

    public function getHandoffText()
    {
        return __('Use your passkey to finish signing in.', 'fluent-security');
    }

    public function getLoginMedia()
    {
        return 'two_factor_passkey';
    }

    /**
     * Whether this site can offer passkeys at all.
     *
     * @return bool
     */
    public static function isEnabledForAnyRole()
    {
        if (!RelyingParty::isSupported()) {
            return false;
        }

        if (Helper::getSetting('passkey_2fa') !== 'yes') {
            return false;
        }

        /*
         * Offering passkeys as a way in is itself a statement that everyone may hold one,
         * so the role list stops being consulted - see isAllowedForUser().
         */
        if (PasskeyLogin::isPrimaryLoginEnabled()) {
            return true;
        }

        $roles = Helper::getSetting('passkey_2fa_roles');

        return is_array($roles) && (bool)$roles;
    }

    /**
     * Whether this user may register one.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isAllowedForUser($user)
    {
        $user = self::resolveUser($user);

        /*
         * The secure-context test stays in front of everything, requirement included. It
         * is not a policy but a fact about the browser: over plain http no passkey can be
         * created at all, so "allowed" here would be a promise the platform refuses to
         * keep.
         */
        if (!$user || !RelyingParty::isSupported()) {
            return false;
        }

        if (!apply_filters('fluent_auth/passkey_enabled', true, $user)) {
            return false;
        }

        // Requiring a second factor grants the methods that can satisfy it - see
        // TotpTwoFaMethod::isAllowedForUser() for why.
        if (DeviceRequirement::isRequiredForUser($user)) {
            return true;
        }

        if (Helper::getSetting('passkey_2fa') !== 'yes') {
            return false;
        }

        /*
         * With passkeys offered as a login method the role list no longer applies, and
         * the settings screen disables it to say so.
         *
         * The reasoning is that the two switches answer different questions. The role
         * list answers "whose *second* step may be a passkey", which is a policy about
         * how tightly to guard an account that already has a password. Offering a
         * passkey on the login form answers "may somebody sign in with one at all", and
         * a subscriber who can is a subscriber who has to be able to register one first.
         * Keeping the list in force would show every visitor a button that silently did
         * nothing for most of them.
         *
         * Enforcement is untouched by this: totp_required_roles still decides who *must*
         * hold a factor, and being allowed to register a passkey has never been the same
         * as being made to. See DeviceRequirement.
         */
        if (PasskeyLogin::isPrimaryLoginEnabled()) {
            return true;
        }

        $roles = Helper::getSetting('passkey_2fa_roles');

        // Naming no roles turns the method off, exactly as it does for the authenticator app.
        if (!$roles || !is_array($roles)) {
            return false;
        }

        return (bool)array_intersect($roles, array_values($user->roles));
    }

    /**
     * Whether this user can be challenged with a passkey right now.
     *
     * The extra condition beyond "enrolled" is the important one. A passkey has no
     * recovery code of its own: lose every registered authenticator and there is
     * nothing to type instead. So a user is only ever asked for one while they still
     * have an authenticator app to fall back to, or while the site has been told
     * explicitly that it may stand alone.
     *
     * Without that rule, someone who registers a passkey on their laptop and later
     * signs in from a browser that cannot do WebAuthn is looking at a form no one can
     * answer - which is the lockout that BaseTwoFaMethod warns about, arriving by a
     * different road.
     *
     * @param $user \WP_User
     * @return bool
     */
    /**
     * Registered, whatever the login flow would currently do with it.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public function isEnrolledForUser($user)
    {
        return self::isEnrolled($user);
    }

    public function isAvailableForUser($user)
    {
        if (!self::isAllowedForUser($user) || !self::isEnrolled($user)) {
            return false;
        }

        return self::hasFallback($user);
    }

    /**
     * Whether something else could answer for this account if the passkey cannot.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function hasFallback($user)
    {
        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        /*
         * Recovery codes, which are now the account's rather than the authenticator
         * app's. This is the arm that makes a passkey-only account workable: something
         * printed and filed is exactly the fallback a device-bound credential lacks.
         */
        if (RecoveryCodes::hasAny($user)) {
            return true;
        }

        // Or an authenticator app, which can be answered by typing.
        if (TotpTwoFaMethod::isEnrolled($user)) {
            return true;
        }

        /*
         * Or a second passkey. Two registered credentials means two devices, which is
         * the redundancy a single one lacks: a laptop and a phone, or a security key and
         * the password manager that syncs.
         *
         * One is deliberately not enough even when it reports itself as synced. That
         * flag says the credential may be copied between devices, not that it has been,
         * and a user locked out of the account holding it is locked out of all the
         * copies at once.
         */
        if (PasskeyStore::countForUser($user) >= 2) {
            return true;
        }

        /*
         * A site that has thought about it can allow a lone passkey - the honest case is
         * one whose administrators are ready to remove credentials from a profile screen
         * when somebody calls. It has to be said out loud rather than arrived at by a
         * user enrolling a single device.
         */
        return (bool)apply_filters('fluent_auth/passkey_allow_without_fallback', false, $user);
    }

    /**
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isEnrolled($user)
    {
        return PasskeyStore::countForUser($user) > 0;
    }

    /**
     * Issues the challenge this login will be answered with.
     *
     * @param $user \WP_User
     * @return array
     */
    public function prepareChallenge($user)
    {
        try {
            $challenge = Ceremony::createChallenge();
        } catch (WebAuthnException $e) {
            return ['columns' => [], 'secret' => null];
        }

        return [
            'columns' => [
                self::CHALLENGE_COLUMN => Base64Url::encode($challenge)
            ],
            'secret'  => null
        ];
    }

    /**
     * @param $user \WP_User
     * @param $logHash object
     * @param $request array
     * @return bool|\WP_Error
     */
    public function verifyProof($user, $logHash, $request)
    {
        /*
         * Not sanitize_text_field: this is a JSON document carrying base64url, and that
         * filter strips characters out of the middle of it rather than rejecting it -
         * turning a good assertion into a malformed one. It is decoded strictly instead,
         * and every field inside is validated as base64url before it is used.
         */
        /*
         * A recovery code answers this form too. Somebody reaching for one has usually
         * lost the device the passkey lives on, so refusing it here and sending them to
         * find another screen is refusing them the one thing they have left.
         */
        $typed = Arr::get((array)$request, 'login_passcode');

        if (is_string($typed) && $typed !== '') {
            $normalised = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', sanitize_text_field($typed)));

            if (!RecoveryCodes::looksLikeCode($normalised)) {
                return new \WP_Error(
                    'passkey_bad_recovery',
                    __('That does not look like a recovery code. Please check and try again.', 'fluent-security')
                );
            }

            return RecoveryCodes::consume($user, $normalised);
        }

        $raw = Arr::get((array)$request, 'webauthn_response');
        $raw = is_string($raw) ? wp_unslash($raw) : '';

        if ($raw === '') {
            return new \WP_Error(
                'passkey_missing',
                __('No passkey response was provided. Please try again.', 'fluent-security')
            );
        }

        $response = json_decode($raw, true);

        if (!is_array($response)) {
            return new \WP_Error(
                'passkey_malformed',
                __('The passkey response could not be read. Please try again.', 'fluent-security')
            );
        }

        $challenge = Base64Url::decode((string)$logHash->{self::CHALLENGE_COLUMN});

        if ($challenge === false) {
            return new \WP_Error(
                'passkey_no_challenge',
                __('This login has expired. Please start again.', 'fluent-security')
            );
        }

        $rawId = Arr::get($response, 'rawId');
        $credential = PasskeyStore::findByCredentialId(is_string($rawId) ? $rawId : '');

        if (!$credential) {
            return new \WP_Error(
                'passkey_unknown',
                __('That passkey is not registered for this site.', 'fluent-security')
            );
        }

        try {
            $signCount = Assertion::verify($response, $credential, $challenge, $user);
        } catch (WebAuthnException $e) {
            /*
             * The reason is logged for the site and withheld from the browser. Telling
             * whoever sent this which check it failed tells them what to change, and
             * every one of these outcomes means the same thing to a legitimate user.
             */
            do_action('fluent_auth/passkey_verification_failed', $user, $e->getMessage());

            return false;
        }

        PasskeyStore::touch($credential, $signCount);

        do_action('fluent_auth/passkey_verified', $user, $credential);

        return true;
    }

    /**
     * @param $data array
     * @return string
     */
    public function renderForm($data = [])
    {
        $loginHash = sanitize_text_field((string)Arr::get($data, 'login_hash'));
        $redirectTo = Arr::get($data, 'redirect_to');
        $redirectTo = $redirectTo ? esc_url_raw($redirectTo) : '';

        $options = $this->getRequestOptionsForPendingLogin($loginHash);

        if (!$options) {
            return $this->renderUnavailable();
        }

        ob_start();
        ?>
        <form
            style="margin-top: 20px;margin-left: 0;padding: 26px 24px 34px;font-weight: 400;overflow: hidden;background: #fff;border: 1px solid #c3c4c7;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);"
            class="fls_2fs" id="fls_2fa_form">
            <input type="hidden" name="login_hash" value="<?php echo esc_attr($loginHash); ?>"/>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirectTo); ?>"/>
            <input type="hidden" name="webauthn_response" id="fls_passkey_response" value=""/>

            <div class="user-pass-wrap">
                <p style="margin-bottom: 20px;">
                    <?php esc_html_e('Confirm it is you with the passkey you registered for this site.', 'fluent-security'); ?>
                </p>

                <div id="fls_passkey_status" style="margin: 0 0 16px;font-size: 13px;color: #646970;"></div>

                <button type="button" id="fls_passkey_start"
                        style="display: block; cursor: pointer; width: 100%;border: 1px solid #2271b1;background: #2271b1;color: #fff;text-decoration: none;text-shadow: none;min-height: 32px;line-height: 2.30769231;padding: 4px 12px;font-size: 13px;border-radius: 3px;">
                    <?php esc_html_e('Use your passkey', 'fluent-security'); ?>
                </button>

                <?php
                /*
                 * The form the page's own script submits. Hidden because the ceremony has
                 * to run first: the visible button above collects the assertion and only
                 * then asks this one to submit, so the shared login handler posts a form
                 * that has already been filled in.
                 */
                ?>
                <button type="submit" id="fls_2fa_confirm" style="display:none;" aria-hidden="true"></button>

                <?php if (RecoveryCodes::hasAny((int)$this->getPendingUserId($loginHash))) : ?>
                    <div style="margin-top: 18px;border-top: 1px solid #dcdcde;padding-top: 16px;">
                        <label for="login_passcode" style="font-size:13px;">
                            <?php esc_html_e('Lost the device? Enter a recovery code instead.', 'fluent-security'); ?>
                        </label>
                        <input style="font-size: 14px;letter-spacing: 2px;margin-top:6px;"
                               type="text" name="login_passcode" id="login_passcode"
                               class="input" size="20" autocomplete="one-time-code"
                               placeholder="<?php esc_attr_e('Recovery code', 'fluent-security'); ?>"/>
                        <button type="submit" form="fls_2fa_form" id="fls_passkey_recovery"
                                style="margin-top:10px;display:block;cursor:pointer;width:100%;border:1px solid #c3c4c7;background:#f6f7f7;color:#2c3338;min-height:32px;line-height:2.30769231;padding:4px 12px;font-size:13px;border-radius:3px;">
                            <?php esc_html_e('Use recovery code', 'fluent-security'); ?>
                        </button>
                    </div>
                <?php endif; ?>

                <?php if ($this->hasSwitchableFallback($loginHash)) : ?>
                    <p style="margin: 16px 0 0;font-size: 13px;text-align: center;">
                        <a href="<?php echo esc_url(TwoFaService::getSwitchUrl($loginHash)); ?>">
                            <?php esc_html_e('Use your authenticator app instead', 'fluent-security'); ?>
                        </a>
                    </p>
                <?php endif; ?>
            </div>
        </form>

        <?php
        /*
         * Data only. The ceremony itself lives in src/public/login_helper.js, because
         * this form is also delivered to the front end as a string and installed with
         * innerHTML, which parses an island like this one into an element but never
         * runs a <script> that holds code.
         */
        ?>
        <script type="application/json" id="fls_passkey_config"><?php
            echo wp_json_encode([
                'options'  => $options,
                'messages' => [
                    'unsupported' => __('This browser cannot use passkeys. Try another browser, or use your authenticator app.', 'fluent-security'),
                    'prompting'   => __('Waiting for your passkey…', 'fluent-security'),
                    'cancelled'   => __('That was cancelled. You can try again.', 'fluent-security'),
                    'verifying'   => __('Checking your passkey…', 'fluent-security')
                ]
            ]); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        ?></script>
        <?php

        return ob_get_clean();
    }

    /**
     * @return string
     */
    private function renderUnavailable()
    {
        ob_start();
        ?>
        <div style="margin-top: 20px;padding: 26px 24px;background: #fff;border: 1px solid #c3c4c7;">
            <p style="margin: 0;">
                <?php esc_html_e('This login can no longer be completed with a passkey. Please start again.', 'fluent-security'); ?>
            </p>
        </div>
        <?php

        return ob_get_clean();
    }

    /**
     * The request options for the challenge that is currently outstanding.
     *
     * Read back from the pending row rather than generated here, so that what the form
     * asks the authenticator to sign is the same challenge verifyProof() will check
     * against. Generating a fresh one at render time would mean a reload quietly
     * invalidated the login in progress.
     *
     * @param $loginHash string
     * @return array|null
     */
    private function getRequestOptionsForPendingLogin($loginHash)
    {
        $row = $this->getPendingRow($loginHash);

        if (!$row) {
            return null;
        }

        $challenge = Base64Url::decode((string)$row->{self::CHALLENGE_COLUMN});

        if ($challenge === false) {
            return null;
        }

        $credentials = PasskeyStore::getForUser((int)$row->user_id);

        if (!$credentials) {
            return null;
        }

        return Assertion::getRequestOptions($challenge, $credentials);
    }

    /**
     * @param $loginHash string
     * @return int
     */
    private function getPendingUserId($loginHash)
    {
        $row = $this->getPendingRow($loginHash);

        return $row ? (int)$row->user_id : 0;
    }

    /**
     * @param $loginHash string
     * @return bool
     */
    private function hasSwitchableFallback($loginHash)
    {
        $row = $this->getPendingRow($loginHash);

        if (!$row) {
            return false;
        }

        $user = get_user_by('ID', (int)$row->user_id);

        return $user instanceof \WP_User && TotpTwoFaMethod::isEnrolled($user);
    }

    /**
     * @param $loginHash string
     * @return object|null
     */
    private function getPendingRow($loginHash)
    {
        if (!$loginHash) {
            return null;
        }

        $row = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $loginHash)
            ->where('status', 'issued')
            ->first();

        return $row ? $row : null;
    }

    /**
     * @param $user \WP_User|int
     * @return \WP_User|false
     */
    private static function resolveUser($user)
    {
        if ($user instanceof \WP_User) {
            return $user;
        }

        if (!is_numeric($user)) {
            return false;
        }

        $user = get_user_by('ID', (int)$user);

        return $user instanceof \WP_User ? $user : false;
    }
}
