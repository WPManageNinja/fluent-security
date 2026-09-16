<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\QrCode;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Ceremony;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * The step that stands in front of a user who owes a device factor and has none.
 *
 * Not a proof of anything the user already held - which is what every other method
 * here is - but the login flow does not need it to be. What it needs is an answer to
 * "does this user still owe something before a cookie is issued", and for somebody
 * under a policy they have not met yet the answer is yes. Saying so in the same
 * vocabulary as the other methods is what moves enforcement to the only place it can
 * be complete.
 *
 * It used to live at the door of wp-admin instead - TotpEnforcementHandler, on
 * `admin_init`. That is after the auth cookie has been issued, so the user it was
 * holding back already had a working session: the gate hid the dashboard from them
 * while REST, XML-RPC and admin-ajax stayed open, to this plugin and to every other
 * plugin on the site. Here, there is no session to hold back. The password was right
 * and the cookie is still not sent.
 *
 * The proof it asks for is real, incidentally, and that is what makes it safe to sign
 * the user in at the end: finishing enrollment means producing a current code from the
 * app just paired, which is the same evidence the challenge form asks for every day
 * afterwards.
 */
class EnrollmentTwoFaMethod extends BaseTwoFaMethod
{
    /**
     * Fits `fls_login_hashes`.`use_type`, which is varchar(20).
     */
    const KEY = 'enroll_device';

    /**
     * Where the outstanding WebAuthn registration challenge is kept.
     *
     * The pending login row's own column, as PasskeyTwoFaMethod uses it for the
     * assertion challenge - it is a nonce whose whole job is to be unrepeatable, so
     * there is nothing to hash, and it belongs to this login attempt rather than to the
     * account.
     */
    const CHALLENGE_COLUMN = 'two_fa_code_hash';

    /**
     * Whether this request is the one that just completed an enrollment.
     *
     * An instance property because TwoFaService caches one instance per method and
     * hands the same one to verifyProof() and then to getSuccessResponse(), inside a
     * single request. It is never read in any other.
     *
     * @var bool
     */
    private $justEnrolled = false;

    public function getKey()
    {
        return self::KEY;
    }

    public function getTitle()
    {
        return __('Set up two-factor authentication', 'fluent-security');
    }

    /**
     * What the user will be holding once this is done.
     *
     * Saying DEVICE rather than inventing a fourth factor is what keeps
     * TwoFaService::getRequiredMethod() from offering this to somebody who arrived by a
     * route that already proved a device.
     *
     * @return string
     */
    public function getSatisfiedFactor()
    {
        return AuthFactor::DEVICE;
    }

    public function getHandoffText()
    {
        return __('Your account needs two-factor authentication before you can sign in.', 'fluent-security');
    }

    /**
     * Only for somebody who is under the policy and has not met it.
     *
     * @param $user \WP_User
     * @return bool
     */
    public function isAvailableForUser($user)
    {
        return DeviceRequirement::isOwedBy($user);
    }

    /**
     * Never, and it is not a method being off.
     *
     * This is the step that stands in front of somebody who owes a factor, not a factor
     * they could hold - so it can never be the thing that makes a requirement
     * enforceable. Answering anything else would let the requirement satisfy itself:
     * isEnforceable() would see this, decide the requirement stands, and this would be
     * available because the requirement stands.
     *
     * @return bool
     */
    public function isSwitchedOn()
    {
        return false;
    }

    /**
     * Has a *fresh* secret ready before the form that shows it is drawn.
     *
     * Fresh, and not the pending one already on file, because of who can reach this
     * screen. Everywhere else setup is offered the visitor is already signed in; here
     * the only thing they have shown is the password. Handing back an existing pending
     * secret would mean an attacker who knows the password can sign in, read the setup
     * key, abandon the form, and wait: the real account holder is later shown the same
     * key, scans it, activates it, and the two of them now share an authenticator the
     * site reports as the account's protection. That is worse than the attacker simply
     * enrolling their own, because nothing ever looks wrong.
     *
     * One secret per login attempt closes it. The cost is that two attempts racing each
     * other invalidate one another's QR code, which is a retry - not a shared factor.
     *
     * @param $user \WP_User
     * @return array
     */
    public function prepareChallenge($user)
    {
        if (self::canOfferTotp($user)) {
            TotpTwoFaMethod::regeneratePendingSecret($user);
        }

        $columns = [];

        /*
         * A passkey challenge is raised alongside, so the screen can offer both and let
         * the browser decide which is possible. Raised here rather than over a second
         * request because there is no session yet to authorise one: the pending row is
         * the only credential this screen has, and it already exists.
         */
        if (self::canOfferPasskey($user)) {
            try {
                $columns[self::CHALLENGE_COLUMN] = Base64Url::encode(Ceremony::createChallenge());
            } catch (WebAuthnException $e) {
                // No randomness for a challenge. The authenticator app still works.
            }
        }

        return [
            'columns' => $columns,
            'secret'  => null
        ];
    }

    /**
     * Whether a passkey is worth putting on the screen for this user.
     *
     * The site-level half only. Whether the browser in front of them can actually make
     * one is a question only the browser can answer, and it is asked there - see the
     * capability probe in renderForm(). This is what stops the offer appearing at all on
     * a site served over plain http, where no passkey can be created however modern the
     * browser is.
     *
     * @param $user \WP_User
     * @return bool
     */
    public static function canOfferPasskey($user)
    {
        return $user instanceof \WP_User && PasskeyTwoFaMethod::isAllowedForUser($user);
    }

    /**
     * Whether an authenticator app is worth putting on the screen for this user.
     *
     * The mirror of canOfferPasskey(), and it did not exist because it did not need to:
     * a requirement used to grant the app whatever the site switch said, so the app was
     * always offerable to anybody who reached this screen. It is not any more - a method
     * that is switched off is off for everybody - and without this the screen paired an
     * app that could never satisfy the requirement. The user enrolled, activation
     * succeeded, they still owed a factor, and the next sign-in regenerated the secret
     * and killed the app they had just paired.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function canOfferTotp($user)
    {
        return TotpTwoFaMethod::isAllowedForUser($user);
    }

    /**
     * @param $data array
     * @return string
     */
    public function renderForm($data = [])
    {
        $logHash = Arr::get($data, 'login_hash');
        $redirectTo = Arr::get($data, 'redirect_to');

        if ($redirectTo) {
            $redirectTo = esc_url_raw($redirectTo);
        }

        $row = $this->resolveRowFromHash($logHash);
        $user = $row ? get_user_by('ID', $row->user_id) : false;
        $user = $user instanceof \WP_User ? $user : false;

        $secret = ($user && self::canOfferTotp($user)) ? TotpTwoFaMethod::getOrCreatePendingSecret($user) : '';
        $passkeyOptions = $this->getPasskeyOptions($user, $row);

        ob_start();
        ?>
        <form
            style="margin-top: 20px;margin-left: 0;padding: 26px 24px 34px;font-weight: 400;overflow: hidden;background: #fff;border: 1px solid #c3c4c7;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);"
            class="fls_2fs" id="fls_2fa_form">
            <input type="hidden" name="login_hash" value="<?php echo esc_attr($logHash); ?>"/>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirectTo); ?>"/>
            <input type="hidden" name="fls_enroll_credential" id="fls_enroll_credential" value=""/>
            <input type="hidden" name="fls_enroll_transports" id="fls_enroll_transports" value=""/>

            <?php if (!$secret && !$passkeyOptions) : ?>
                <p style="margin: 0;color:#b32d2e;">
                    <?php esc_html_e('Two-factor authentication cannot be set up on this server. Please contact your host.', 'fluent-security'); ?>
                </p>
            <?php else : ?>
                <p style="margin: 0 0 16px;">
                    <strong><?php esc_html_e('Two-factor authentication is required for your account.', 'fluent-security'); ?></strong>
                </p>

                <?php if ($passkeyOptions) : ?>
                    <!--
                        Hidden until the browser has been asked whether it can do this at
                        all. Rendering it visible and letting the probe take it away would
                        show every user an option that half of them cannot use, for as long
                        as the promise takes to resolve.
                    -->
                    <div id="fls_enroll_passkey"<?php echo $secret ? ' style="display: none;"' : ''; ?>>
                        <p style="margin: 0 0 16px;">
                            <?php esc_html_e('Use your fingerprint, face or screen lock. Nothing to install, and nothing to type.', 'fluent-security'); ?>
                        </p>
                        <button type="button" id="fls_enroll_passkey_start"
                                style="display: block; cursor: pointer; width: 100%;border: 1px solid #2271b1;background: #2271b1;color: #fff;text-shadow: none;min-height: 32px;line-height: 2.30769231;padding: 4px 12px;font-size: 13px;border-radius: 3px;">
                            <?php esc_html_e('Set up and sign in', 'fluent-security'); ?>
                        </button>
                        <p id="fls_enroll_passkey_status" style="margin: 10px 0 0;font-size: 12px;color: #646970;min-height: 16px;"></p>
                        <?php if ($secret) : ?>
                            <p style="margin: 16px 0 0;text-align: center;">
                                <a href="#" id="fls_enroll_show_app"><?php esc_html_e('Use an authenticator app instead', 'fluent-security'); ?></a>
                            </p>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <?php
                /*
                 * Not drawn at all where the app is switched off, rather than drawn empty.
                 *
                 * Three versions of this have been wrong in three different ways. It used
                 * to say "a secret could not be generated on this server", blaming the host
                 * for a decision the owner made, under a finish button that could not
                 * finish anything. Hiding it instead left the passkey pane - which the
                 * script only reveals once a platform authenticator answers - as the sole
                 * offer, so a browser without one showed a heading and nothing else.
                 *
                 * Absent is what the script keys on: with no app pane there is nothing to
                 * fall back to, so it leaves the passkey offer visible and says so when the
                 * browser cannot do it. See initEnrollment() in login_helper.js.
                 */
                ?>
                <?php if ($secret) : ?>
                <div id="fls_enroll_app">
                        <p style="margin: 0 0 16px;">
                            <?php esc_html_e('Scan this with an authenticator app, then enter the code it shows to finish signing in.', 'fluent-security'); ?>
                        </p>
                        <?php $this->renderSecret($secret, $user); ?>

                        <label for="fls_enroll_code"><?php esc_html_e('Code from your app', 'fluent-security'); ?></label>
                        <div class="wp-pwd">
                            <input style="font-size: 14px;letter-spacing: 3px;"
                                   placeholder="000000"
                                   type="text"
                                   inputmode="numeric"
                                   autocomplete="one-time-code"
                                   name="fls_enroll_code" id="fls_enroll_code" class="input" size="20"/>
                        </div>
                        <p style="margin: 12px 0 20px;font-size: 12px;color: #646970;">
                            <?php esc_html_e('Nothing changes until you enter a code and finish.', 'fluent-security'); ?>
                        </p>
                    <div>
                        <button
                            style="display: block; cursor: pointer; width: 100%;border: 1px solid #2271b1;background: #2271b1;color: #fff;text-decoration: none;text-shadow: none;min-height: 32px;line-height: 2.30769231;padding: 4px 12px;font-size: 13px;border-radius: 3px;"
                            id="fls_2fa_confirm" type="submit">
                            <?php esc_html_e('Finish setup and sign in', 'fluent-security'); ?>
                        </button>
                    </div>
                    <?php if ($passkeyOptions) : ?>
                        <p style="margin: 16px 0 0;text-align: center;display: none;" id="fls_enroll_show_passkey_wrap">
                            <a href="#" id="fls_enroll_show_passkey"><?php esc_html_e('Use a passkey instead', 'fluent-security'); ?></a>
                        </p>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>
        </form>

        <?php if ($passkeyOptions) : ?>
            <?php
            /*
             * Data only - see PasskeyTwoFaMethod::renderForm(). The behaviour is in
             * src/public/login_helper.js so that it survives being installed with
             * innerHTML on the front end.
             */
            ?>
            <script type="application/json" id="fls_enroll_config"><?php
                echo wp_json_encode([
                    'options'  => $passkeyOptions,
                    'messages' => [
                        'prompting'   => __('Waiting for your passkey…', 'fluent-security'),
                        /*
                         * Two versions, because one of them is a lie on a screen where the
                         * app is switched off - there is nothing to fall back to and the
                         * link that used to say so is not rendered either.
                         */
                        'cancelled'   => $secret
                            ? __('That was cancelled. You can try again, or use an authenticator app.', 'fluent-security')
                            : __('That was cancelled. You can try again.', 'fluent-security'),
                        'saving'      => __('Finishing sign in…', 'fluent-security'),
                        /*
                         * Only ever shown where the passkey is the whole screen. Everywhere
                         * else a browser that cannot make one is simply left on the app,
                         * and saying anything would be noise.
                         */
                        'unsupported' => __('This browser cannot set up a passkey. Try another browser, or a device with Touch ID, Windows Hello or a security key.', 'fluent-security')
                    ]
                ]); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            ?></script>
        <?php endif; ?>
        <?php

        return ob_get_clean();
    }

    /**
     * What the browser needs to create a credential, or null if it should not be asked.
     *
     * @param $user \WP_User|false
     * @param $row object|null
     * @return array|null
     */
    private function getPasskeyOptions($user, $row)
    {
        if (!$row || !self::canOfferPasskey($user)) {
            return null;
        }

        $stored = isset($row->{self::CHALLENGE_COLUMN}) ? (string)$row->{self::CHALLENGE_COLUMN} : '';
        $challenge = $stored === '' ? false : Base64Url::decode($stored);

        if ($challenge === false || $challenge === '') {
            return null;
        }

        $existing = [];

        // Section 7.1 step 20 the polite way round: an authenticator that already holds a
        // credential for this account refuses rather than silently making a second.
        foreach (PasskeyStore::getForUser($user) as $credential) {
            $existing[] = $credential->credential_id;
        }

        return Registration::getCreationOptions($user, $challenge, $existing);
    }

    /**
     * The QR code and the key underneath it.
     *
     * Drawn on this server rather than by a chart service, because the URI carries the
     * shared secret - handing it to a third party to render would hand over the second
     * factor with it.
     *
     * @param $secret string
     * @param $user \WP_User
     * @return void
     */
    private function renderSecret($secret, $user)
    {
        $uri = TotpProvider::getProvisioningUri($secret, $user->user_login, get_bloginfo('name'));

        $qr = QrCode::svg($uri, [
            'size'  => 200,
            'label' => __('QR code for setting up your authenticator app', 'fluent-security')
        ]);

        if ($qr) {
            ?>
            <div style="text-align: center;margin-bottom: 16px;">
                <span style="display:inline-block;padding:10px;background:#fff;border:1px solid #c3c4c7;">
                    <?php echo $qr; // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from integers, the label is escaped ?>
                </span>
            </div>
            <?php
        }

        ?>
        <p style="margin: 0 0 4px;"><strong><?php esc_html_e('Setup key', 'fluent-security'); ?></strong></p>
        <!--
            Not an input: the key is longer than a phone-width field, and a field crops
            what will not fit rather than wrapping it, which leaves people typing in half
            a key. The form does not submit it either, so it need not be a field.
        -->
        <div style="word-break: break-all;font-family: Menlo, Consolas, monospace;letter-spacing: 1px;margin-bottom: 4px;"><?php echo esc_html(trim(chunk_split($secret, 4, ' '))); ?></div>
        <p style="margin: 0 0 20px;font-size: 12px;color: #646970;">
            <?php esc_html_e('Cannot scan the code? Choose "enter a setup key" in your app and paste this in. Spaces do not matter.', 'fluent-security'); ?>
        </p>
        <?php
    }

    /**
     * Pairs the app, and only then lets the login finish.
     *
     * @param $user \WP_User
     * @param $logHash object
     * @param $request array
     * @return bool|\WP_Error
     */
    public function verifyProof($user, $logHash, $request)
    {
        /*
         * Re-asked here rather than trusted from when the form was drawn. A user who
         * enrolled in another tab while this one sat open owes nothing any more, and
         * activating a second secret over the one they just paired would break the app
         * they are holding.
         */
        if (!DeviceRequirement::isOwedBy($user)) {
            return new \WP_Error(
                'already_enrolled',
                __('Two-factor authentication is already set up on this account. Please sign in again.', 'fluent-security')
            );
        }

        /*
         * Which proof arrived decides which enrollment this was. A passkey response is
         * only ever present because the user pressed the passkey button and their
         * authenticator answered; everything else is the authenticator app.
         */
        $credential = Arr::get($request, 'fls_enroll_credential');

        if (is_string($credential) && $credential !== '') {
            return $this->enrolPasskey($user, $logHash, $credential, $request);
        }

        if (!self::canOfferTotp($user)) {
            return new \WP_Error(
                'totp_not_available',
                __('Authenticator apps are switched off on this site. Please use a passkey.', 'fluent-security')
            );
        }

        $secret = TotpTwoFaMethod::getPendingSecret($user->ID);

        if (!$secret) {
            return new \WP_Error(
                'setup_expired',
                __('That setup has expired. Please sign in again to start over.', 'fluent-security')
            );
        }

        $submitted = sanitize_text_field((string)Arr::get($request, 'fls_enroll_code', ''));

        /*
         * Nothing typed is malformed input, not a wrong guess, so it must not spend one
         * of the five attempts - see BaseTwoFaMethod::verifyProof. It matters more here
         * than on the challenge form: this is now the only route to a session, so
         * burning the row on an autofocused empty field leaves the user having to start
         * the whole login again.
         */
        if ($submitted === '') {
            return new \WP_Error(
                'invalid_code',
                __('Please enter the code from your authenticator app', 'fluent-security')
            );
        }

        $counter = TotpProvider::verify($secret, $submitted);

        // A wrong code, which is what the attempt cap in TwoFaHandler is counting.
        if ($counter === false) {
            return false;
        }

        /*
         * The confirming code is spent as part of activation, so the very code just
         * typed here cannot be turned around and replayed at the login form.
         */
        if (!TotpTwoFaMethod::activate($user->ID, $secret, $counter)) {
            return new \WP_Error(
                'activation_failed',
                __('Two-factor authentication could not be saved. Please try again.', 'fluent-security')
            );
        }

        $this->justEnrolled = true;

        do_action('fluent_auth/device_factor_enrolled', $user->ID, 'totp');

        return true;
    }

    /**
     * Registers the passkey the browser has just produced.
     *
     * The challenge is read from the pending login row rather than from a transient
     * keyed on the user, because this happens with no session: the row is the only thing
     * that knows which login attempt is being finished, and two attempts must not be
     * able to answer each other's challenge.
     *
     * @param $user \WP_User
     * @param $logHash object
     * @param $credential string the JSON the browser sent
     * @param $request array
     * @return bool|\WP_Error
     */
    private function enrolPasskey($user, $logHash, $credential, $request)
    {
        if (!self::canOfferPasskey($user)) {
            return new \WP_Error(
                'passkey_unavailable',
                __('Passkeys cannot be set up on this site.', 'fluent-security')
            );
        }

        $stored = isset($logHash->{self::CHALLENGE_COLUMN}) ? (string)$logHash->{self::CHALLENGE_COLUMN} : '';
        $challenge = $stored === '' ? false : Base64Url::decode($stored);

        if ($challenge === false || $challenge === '') {
            return new \WP_Error(
                'setup_expired',
                __('That setup has expired. Please sign in again to start over.', 'fluent-security')
            );
        }

        $response = json_decode(wp_unslash($credential), true);

        if (!is_array($response)) {
            return new \WP_Error(
                'invalid_credential',
                __('The passkey response could not be read.', 'fluent-security')
            );
        }

        try {
            $verified = Registration::verify($response, $challenge);
        } catch (WebAuthnException $e) {
            do_action('fluent_auth/passkey_registration_failed', $user, $e->getMessage());

            return new \WP_Error(
                'passkey_unverified',
                __('That passkey could not be verified. Please try again.', 'fluent-security')
            );
        }

        $transports = Arr::get($request, 'fls_enroll_transports');
        $transports = is_string($transports) ? json_decode(wp_unslash($transports), true) : [];

        $added = PasskeyStore::add($user, $verified, __('Passkey', 'fluent-security'), (array)$transports);

        if (is_wp_error($added)) {
            return $added;
        }

        $this->justEnrolled = true;

        do_action('fluent_auth/device_factor_enrolled', $user->ID, 'passkey');

        return true;
    }

    /**
     * Hands the recovery codes over before the browser leaves the page.
     *
     * They are shown once and never again, so a plain redirect here would mint a set
     * nobody ever sees - which is worse than minting none, because the account then
     * looks recoverable and is not.
     *
     * @param $response array
     * @param $user \WP_User
     * @param $logHash object
     * @return array
     */
    public function getSuccessResponse($response, $user, $logHash)
    {
        if (!$this->justEnrolled) {
            return $response;
        }

        /*
         * Minted here rather than in verifyProof(), because this is the first point at
         * which the sign in is known to have succeeded. wp_signon() can still be vetoed
         * after the proof is accepted - by another plugin on `authenticate`, or by
         * core's own multisite checks - and codes generated before that would be codes
         * nobody is ever shown, while RecoveryCodes::hasAny() went on reporting the
         * account as having a set. A profile screen saying "10 unused recovery codes"
         * for codes that were never displayed is the exact failure this handoff exists
         * to prevent.
         *
         * Generated only where the account has none. Somebody enrolling a replacement
         * app still holds the printed set from last time, and replacing it silently
         * would retire codes they have filed somewhere without ever telling them.
         */
        if (RecoveryCodes::hasAny($user->ID)) {
            return $response;
        }

        $codes = RecoveryCodes::generate($user->ID);

        if (!$codes) {
            return $response;
        }

        $response['recovery_codes'] = array_values($codes);
        $response['recovery_message'] = __('Save these recovery codes. They are the only way back in if you lose your device, and they are not shown again.', 'fluent-security');
        $response['recovery_continue'] = __('I have saved them - continue', 'fluent-security');

        return $response;
    }

    /**
     * The pending login row this screen is finishing.
     *
     * The row is the authority here, exactly as it is for a challenge: there is no
     * session on this screen, and the hash is the only credential it has. It carries both
     * the account and the outstanding passkey challenge, which is why the row is returned
     * rather than just the user.
     *
     * @param $logHash string
     * @return object|null
     */
    private function resolveRowFromHash($logHash)
    {
        $logHash = sanitize_text_field((string)$logHash);

        if (!$logHash) {
            return null;
        }

        $row = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $logHash)
            ->where('use_type', self::KEY)
            ->where('status', 'issued')
            ->orderBy('id', 'DESC')
            ->first();

        return $row ? $row : null;
    }
}
