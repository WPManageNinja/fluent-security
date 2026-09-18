<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\LoginAssets;
use FluentAuth\App\Services\QrCode;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Ceremony;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * Setting up a second factor without going into wp-admin.
 *
 * The profile screen is still the natural home for this, but a site that keeps its
 * members out of the admin area has no way to send them there - so the same enrollment
 * is served from wp-login.php, which sits outside wp-admin, is reachable by any signed
 * in user whatever their role, and is already dressed by the login page designer.
 *
 * The class name says Totp and the screen no longer only does that, deliberately. It
 * offered an authenticator app and nothing else, which made it a dead end for the exact
 * population it exists to serve: on a site running passkeys with the app switched off,
 * the enforcement gate of the day redirected a required user here, the page told them an
 * authenticator app was not enabled for their account, and its only control was a
 * Continue link back to the admin area - which redirected them here again. The way out
 * was the profile screen, which this screen's audience cannot reach. So it offers both
 * device factors now, in the same order and the same words as the enrollment step in the
 * login flow (see EnrollmentTwoFaMethod), and the name is left alone because it is a
 * public URL shape that other code and other sites point at.
 *
 * Setting one up is all this screen does. Turning a factor off and drawing a fresh set
 * of recovery codes stay on the profile screen and in the admin enrollment list, so a
 * page anybody can reach cannot be used to weaken an account that is already protected.
 */
class TotpSetupPageHandler
{
    /**
     * wp-login.php honours an unknown action only if something is listening for it,
     * which registering this hook is what does. Same route the email code challenge
     * takes (see TwoFaHandler), for the same reason: it is an auth screen, so it
     * belongs on the auth page rather than in a theme template.
     */
    const LOGIN_ACTION = 'fls_2fa_setup';

    const NONCE_ACTION = 'fls_totp_setup_page';

    public function register()
    {
        add_action('login_form_' . self::LOGIN_ACTION, [$this, 'handle']);
    }

    /**
     * Marks the screen as one the user was offered rather than went looking for, which
     * is what puts a way out of it on the page.
     */
    const NUDGE_ARG = 'fls_offered';

    /**
     * The address to hand out - in a welcome email, a menu, a member area.
     *
     * @param $redirectTo string where to send the user once they are done
     * @param $offered bool whether they were sent here by the post-login offer
     * @return string
     */
    public static function getUrl($redirectTo = '', $offered = false)
    {
        $args = ['action' => self::LOGIN_ACTION];

        if ($redirectTo) {
            $args['redirect_to'] = rawurlencode($redirectTo);
        }

        if ($offered) {
            $args[self::NUDGE_ARG] = '1';
        }

        return add_query_arg($args, wp_login_url());
    }

    /**
     * @return bool
     */
    private function wasOffered()
    {
        return (string)Arr::get($_REQUEST, self::NUDGE_ARG, '') === '1';
    }

    /**
     * @return void
     */
    public function handle()
    {
        if (!is_user_logged_in()) {
            // Sign in first, then come straight back here rather than to the admin area.
            wp_safe_redirect(wp_login_url(self::getUrl($this->getRedirectTo())));
            exit();
        }

        $user = wp_get_current_user();

        if (strtoupper((string)Arr::get($_SERVER, 'REQUEST_METHOD', 'GET')) === 'POST') {
            $this->handleSubmit($user);
        }

        $this->render($user);
    }

    /**
     * The submission always redirects back to this screen rather than rendering the
     * outcome directly: the recovery codes are shown once, and a reload that re-posts a
     * spent code would take them away again before they had been written down.
     *
     * @param $user \WP_User
     * @return void
     */
    private function handleSubmit($user)
    {
        $notice = $this->processSubmission($user);

        if ($notice) {
            TotpProfileHandler::setNotice(
                $user->ID,
                Arr::get($notice, 'type'),
                Arr::get($notice, 'message'),
                (array)Arr::get($notice, 'codes', [])
            );
        }

        /*
         * The offer is carried back too. A mistyped code that dropped it would leave
         * somebody who never asked to be here with no way out but the back button.
         */
        wp_safe_redirect(self::getUrl($this->getRedirectTo(), $this->wasOffered()));
        exit();
    }

    /**
     * Registers whichever factor was submitted, or says why it could not be.
     *
     * Public and returning what to say rather than saying it, because this is the whole
     * of the decision - the redirect around it is three lines - and a step that hands
     * out a second factor is worth asking about directly from a test.
     *
     * @param $user \WP_User
     * @return array|false what to tell the user, or false when there is nothing to say
     */
    public function processSubmission($user)
    {
        if (!wp_verify_nonce(sanitize_text_field((string)Arr::get($_POST, '_fls_totp_nonce', '')), self::NONCE_ACTION)) {
            return [
                'type'    => 'error',
                'message' => __('That form had been open too long. Please try again.', 'fluent-security')
            ];
        }

        /*
         * Which proof arrived decides which enrollment this was, exactly as it does in
         * EnrollmentTwoFaMethod::verifyProof(). A passkey response is only ever present
         * because the user pressed the passkey button and their authenticator answered;
         * everything else is the authenticator app.
         */
        $credential = Arr::get($_POST, 'fls_setup_credential');

        if (is_string($credential) && $credential !== '') {
            return $this->processPasskey($user, $credential);
        }

        return $this->processTotp($user);
    }

    /**
     * @param $user \WP_User
     * @return array|false
     */
    private function processTotp($user)
    {
        /*
         * Both are re-checked here: the form was drawn from a policy that may have
         * changed since, and an account that is already paired must not be paired again
         * by a resubmitted form.
         */
        if (TotpTwoFaMethod::isEnrolled($user) || !TotpTwoFaMethod::isAllowedForUser($user)) {
            return false;
        }

        $pending = TotpTwoFaMethod::getPendingSecret($user->ID);

        if (!$pending) {
            return [
                'type'    => 'error',
                'message' => __('That setup has expired. Reload this page to start again.', 'fluent-security')
            ];
        }

        $submitted = sanitize_text_field((string)Arr::get($_POST, 'fls_totp_confirm_code', ''));

        $counter = $submitted === '' ? false : TotpProvider::verify($pending, $submitted);

        if ($counter === false) {
            return [
                'type'    => 'error',
                'message' => __('That code did not match. Check your phone clock is set automatically, then try the current code.', 'fluent-security')
            ];
        }

        /*
         * The confirming step is spent as part of activation, so the very code just
         * typed here cannot be turned around and replayed at the login form.
         */
        TotpTwoFaMethod::activate($user->ID, $pending, $counter);

        /*
         * Only where the account has none, for the reason processPasskey() gives below:
         * RecoveryCodes::generate() clears the filed set first, so minting unconditionally
         * retires codes the user may have printed and put somewhere, without telling them.
         * They are not locked out - the new set is shown - but the paper in the drawer is
         * dead and nothing said so.
         */
        if (RecoveryCodes::hasAny($user->ID)) {
            return [
                'type'    => 'codes',
                'message' => __('Your authenticator app is now set up. Your existing recovery codes still work.', 'fluent-security')
            ];
        }

        return [
            'type'    => 'codes',
            'message' => __('Your authenticator app is now set up. Save these recovery codes - they are the only way back in if you lose the device, and they are not shown again.', 'fluent-security'),
            'codes'   => TotpTwoFaMethod::generateRecoveryCodes($user->ID)
        ];
    }

    /**
     * Registers the passkey the browser has just produced.
     *
     * The ceremony is the profile screen's rather than the login flow's, because the
     * visitor here is signed in: the challenge belongs to a session, so it lives in the
     * same transient PasskeyProfileHandler uses rather than on a pending login row. That
     * also means one outstanding challenge per user across both screens, which is the
     * right number - two tabs racing each other should invalidate one another rather
     * than both succeed.
     *
     * @param $user \WP_User
     * @param $credential string the JSON the browser sent
     * @return array
     */
    private function processPasskey($user, $credential)
    {
        /*
         * Re-asked here rather than trusted from when the form was drawn. A site that
         * switched passkeys off while this page sat open means it.
         */
        if (!PasskeyTwoFaMethod::isAllowedForUser($user)) {
            return [
                'type'    => 'error',
                'message' => __('Passkeys are not enabled for this account.', 'fluent-security')
            ];
        }

        $stored = get_transient(PasskeyProfileHandler::CHALLENGE_TRANSIENT . $user->ID);
        $challenge = is_string($stored) ? Base64Url::decode($stored) : false;

        // Spent on sight, before the response is looked at - see PasskeyProfileHandler.
        delete_transient(PasskeyProfileHandler::CHALLENGE_TRANSIENT . $user->ID);

        if ($challenge === false || $challenge === '') {
            return [
                'type'    => 'error',
                'message' => __('That took too long. Reload this page and try again.', 'fluent-security')
            ];
        }

        $response = json_decode(wp_unslash($credential), true);

        if (!is_array($response)) {
            return [
                'type'    => 'error',
                'message' => __('The passkey response could not be read.', 'fluent-security')
            ];
        }

        try {
            $verified = Registration::verify($response, $challenge);
        } catch (WebAuthnException $e) {
            do_action('fluent_auth/passkey_registration_failed', $user, $e->getMessage());

            return [
                'type'    => 'error',
                'message' => __('That passkey could not be verified. Please try again.', 'fluent-security')
            ];
        }

        $transports = Arr::get($_POST, 'fls_setup_transports');
        $transports = is_string($transports) ? json_decode(wp_unslash($transports), true) : [];

        $added = PasskeyStore::add($user, $verified, __('Passkey', 'fluent-security'), (array)$transports);

        if (is_wp_error($added)) {
            return [
                'type'    => 'error',
                'message' => $added->get_error_message()
            ];
        }

        do_action('fluent_auth/device_factor_enrolled', $user->ID, 'passkey');

        /*
         * Not a nicety. A lone passkey with nothing behind it fails
         * PasskeyTwoFaMethod::hasFallback(), so the login flow will never challenge with
         * it and DeviceRequirement::isSatisfiedBy() rightly answers no - the user would
         * finish this screen, be told they were done, and still be owed the factor they
         * just registered. The codes are what close that, so they are minted here rather
         * than left to a profile screen this audience cannot reach.
         *
         * Only where the account has none. Somebody adding a second device still holds
         * the printed set from last time, and replacing it silently would retire codes
         * they have filed somewhere without telling them.
         */
        if (RecoveryCodes::hasAny($user->ID)) {
            return [
                'type'    => 'codes',
                'message' => __('Your passkey is now set up. You will be asked for it the next time you sign in.', 'fluent-security')
            ];
        }

        $codes = RecoveryCodes::generate($user->ID);

        if (!$codes) {
            return [
                'type'    => 'codes',
                'message' => __('Your passkey is now set up. You will be asked for it the next time you sign in.', 'fluent-security')
            ];
        }

        return [
            'type'    => 'codes',
            'message' => __('Your passkey is now set up. Save these recovery codes - they are the only way back in if you lose the device, and they are not shown again.', 'fluent-security'),
            'codes'   => array_values($codes)
        ];
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    private function render($user)
    {
        $notice = TotpProfileHandler::pullNotice($user->ID);

        add_action('login_head', [$this, 'renderStyles']);

        /*
         * Asked for before login_header(), which is what prints the head this enqueues
         * into. The passkey ceremony lives in that one bundle rather than in an inline
         * <script> here - see LoginAssets.
         */
        LoginAssets::enqueue();

        login_header(__('Two-Factor Authentication', 'fluent-security'), '', null);

        ?>
        <form name="fls_totp_setup" id="fls_totp_setup" method="post"
              action="<?php echo esc_url(self::getUrl($this->getRedirectTo(), $this->wasOffered())); ?>"
              style="margin-top: 20px;margin-left: 0;padding: 26px 24px 34px;font-weight: 400;overflow: hidden;background: #fff;border: 1px solid #c3c4c7;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);">
            <?php
            wp_nonce_field(self::NONCE_ACTION, '_fls_totp_nonce');
            ?>
            <input type="hidden" name="fls_setup_credential" id="fls_setup_credential" value=""/>
            <input type="hidden" name="fls_setup_transports" id="fls_setup_transports" value=""/>
            <?php

            /*
             * People arrive here from a link rather than by looking for it, so the screen
             * has to say what it is - but only once. Where the login page designer is
             * dressing this page it prints a heading of its own above the form, in the
             * site's own type, and a second one underneath would just be a repeat.
             */
            if (!LoginCustomizerHandler::isCustomizedScreen()) :
                ?>
                <h2 style="margin: 0 0 16px;font-size: 18px;line-height: 1.4;">
                    <?php esc_html_e('Set up two-factor authentication', 'fluent-security'); ?>
                </h2>
            <?php
            endif;

            if ($notice) {
                $this->renderNotice($notice);
            }

            $offer = $this->getOffer($user);

            /*
             * Asked only where a passkey is on offer, because asking raises a challenge.
             * It can still come back empty - a server with no randomness for one - which
             * is why the panes are decided on the options rather than on the eligibility.
             */
            $passkeyOptions = $offer['passkey'] ? $this->getPasskeyOptions($user) : null;

            if (!$offer['app'] && !$passkeyOptions) {
                $this->renderNothingToSetUp($user, $offer['secret_failed']);
            } else {
                /*
                 * Somebody who was redirected here was going somewhere else, and a screen
                 * they did not ask for should say who asked for it.
                 */
                // Still owed rather than required - see TotpProfileHandler for why.
                if (DeviceRequirement::isOwedBy($user)) {
                    ?>
                    <div style="border-left: 4px solid #dba617;background:#f6f7f7;padding: 10px 14px;margin: 0 0 20px;">
                        <p style="margin: 0;">
                            <strong><?php esc_html_e('Required for your account.', 'fluent-security'); ?></strong>
                            <?php esc_html_e('Set one up here to carry on using the admin area.', 'fluent-security'); ?>
                        </p>
                    </div>
                    <?php
                } elseif ($this->wasOffered()) {
                    /*
                     * They were signing in, not looking for this. Saying what it is for
                     * is the difference between an offer and an obstacle.
                     *
                     * Worded around the factor rather than the phone, because the offer
                     * on this screen is no longer only an app.
                     */
                    ?>
                    <p style="margin: 0 0 20px;">
                        <?php esc_html_e('Your account is protected by its password. Adding a second step means the password alone is not enough to sign in as you.', 'fluent-security'); ?>
                    </p>
                    <?php
                }

                /*
                 * The passkey leads where both are on, as it does on the enrollment step
                 * in the login flow: it is the one that needs nothing installed and
                 * nothing typed. Which pane is actually on screen is settled by the
                 * browser - see initSetupPasskey() in login_helper.js.
                 */
                if ($passkeyOptions) {
                    $this->renderPasskeySetup($user, $passkeyOptions, $offer['app']);
                }

                if ($offer['app']) {
                    $this->renderSetup($user, $offer['secret'], (bool)$passkeyOptions);
                }

                /*
                 * A way onward, once there is something to go on to.
                 *
                 * Somebody sent here by the enforcement redirect gets no "Not now" link -
                 * they were not offered anything, they were stopped - and a passkey leaves
                 * the offer standing afterwards, because an account can hold several. So
                 * without this a required user who has just registered one is left on this
                 * screen holding their recovery codes and no way forward but the browser's
                 * back button. The authenticator app never showed it because pairing one
                 * takes the whole screen away and replaces it with renderEnrolled().
                 */
                if (DeviceRequirement::holdsEnrolledDevice($user) && !DeviceRequirement::isOwedBy($user)) {
                    $this->renderExit(true);
                }
            }
            ?>
        </form>
        <?php

        login_footer('fls_totp_confirm_code');
        exit();
    }

    /**
     * The login page is laid out for two short fields stacked in a 320px column. This
     * screen carries a QR code, a setup key that reads as nonsense if it is cut in half,
     * and enough explanation to follow without help - so it takes a wider column.
     *
     * Added from render() rather than from register(), so it reaches this screen only
     * and no other login page changes width.
     *
     * @return void
     */
    public function renderStyles()
    {
        ?>
        <style>
            <?php
            /*
             * Only when the page is undressed. The login page designer lays this column
             * out itself - a form panel beside a banner - and a fixed width here would
             * cut across a design somebody chose on purpose.
             */
            if (!LoginCustomizerHandler::isCustomizedScreen()) :
                ?>
            #login {
                width: 440px;
                max-width: calc(100vw - 32px);
            }

            <?php endif; ?>

            /*
             * A key to be read a character at a time and typed into a phone: spaced out
             * for that, wrapping rather than cropping when the column is narrow, and
             * selected whole by a single click so it can be pasted instead.
             */
            #fls_totp_secret_display {
                display: block;
                padding: 8px 10px;
                border: 1px solid #8c8f94;
                border-radius: 3px;
                background: #fff;
                font-family: Menlo, Consolas, monospace;
                font-size: 13px;
                line-height: 1.7;
                letter-spacing: 1px;
                word-break: break-word;
                user-select: all;
            }
        </style>
        <?php
    }

    /**
     * What this screen can offer this user.
     *
     * Public because it is the whole of the decision the page turns on, and because the
     * combination worth asserting is the one that used to be a dead end: no app, no
     * passkey, and a factor still owed. A screen that can lock somebody out of a site by
     * offering them nothing should be something a test can ask directly.
     *
     * The secret is resolved here rather than inside the pane that draws it, because
     * whether there is one decides whether that pane exists at all - and the passkey
     * offer has to know, since it hides itself behind an app pane and is revealed by a
     * browser probe that may well answer no. Drawn second and revealed by nobody is what
     * a server that cannot generate a secret used to produce: a screen with one control
     * on it, invisible.
     *
     * @param $user \WP_User
     * @return array
     */
    public function getOffer($user)
    {
        /*
         * Ordering matters: a role can be required to hold a factor and then have the
         * method taken away underneath it, and being told to set up something the server
         * will refuse to accept is worse than being told nothing.
         */
        $canTotp = !TotpTwoFaMethod::isEnrolled($user) && TotpTwoFaMethod::isAllowedForUser($user);
        $secret = $canTotp ? TotpTwoFaMethod::getOrCreatePendingSecret($user) : '';

        return [
            'app'           => (bool)($canTotp && $secret),
            'passkey'       => PasskeyTwoFaMethod::isAllowedForUser($user),
            'secret'        => (string)$secret,
            // The app was on offer and the server could not produce a secret for it.
            'secret_failed' => (bool)($canTotp && !$secret)
        ];
    }

    /**
     * What the browser needs to create a credential, or null if it should not be asked.
     *
     * Raising the challenge is a side effect of drawing the screen, exactly as it is in
     * EnrollmentTwoFaMethod::prepareChallenge(), so that pressing the button runs the
     * ceremony straight away rather than after a round trip.
     *
     * @param $user \WP_User
     * @return array|null
     */
    private function getPasskeyOptions($user)
    {
        if (!PasskeyTwoFaMethod::isAllowedForUser($user)) {
            return null;
        }

        try {
            $challenge = Ceremony::createChallenge();
        } catch (WebAuthnException $e) {
            // No randomness for a challenge. The authenticator app still works.
            return null;
        }

        set_transient(
            PasskeyProfileHandler::CHALLENGE_TRANSIENT . $user->ID,
            Base64Url::encode($challenge),
            PasskeyProfileHandler::CHALLENGE_TTL
        );

        $existing = [];

        // Section 7.1 step 20 the polite way round: an authenticator that already holds a
        // credential for this account refuses rather than silently making a second.
        foreach (PasskeyStore::getForUser($user) as $credential) {
            $existing[] = $credential->credential_id;
        }

        return Registration::getCreationOptions($user, $challenge, $existing);
    }

    /**
     * The passkey offer.
     *
     * Hidden behind the app where both are on, and revealed by the script once the
     * browser has confirmed it has a platform authenticator - the same trade
     * EnrollmentTwoFaMethod makes, for the same reason: rendering it visible and letting
     * the probe take it away shows half of all users an option they cannot use for as
     * long as the promise takes to resolve. With the app off it is the whole screen, so
     * it is rendered visible and the script says so if the browser cannot oblige.
     *
     * @param $user \WP_User
     * @param $options array
     * @param $hasAppPane bool
     * @return void
     */
    private function renderPasskeySetup($user, $options, $hasAppPane)
    {
        /*
         * An account can hold several passkeys, so the offer stays up after one is
         * registered - but it stops being the thing to do next, and a full width primary
         * button saying "Set up a passkey" directly under "your passkey is now set up"
         * reads as though the first one did not take. Demoted rather than removed:
         * registering the laptop and then the phone is the sensible thing to do here, and
         * this screen is where the people who cannot reach a profile page have to do it.
         */
        $alreadyHasOne = DeviceRequirement::holdsEnrolledDevice($user);
        ?>
        <div id="fls_setup_passkey"<?php echo $hasAppPane ? ' style="display: none;"' : ''; ?>>
            <p style="margin: 0 0 16px;">
                <strong>
                    <?php
                    echo $alreadyHasOne
                        ? esc_html__('Add another passkey', 'fluent-security')
                        : esc_html__('Use a passkey', 'fluent-security');
                    ?>
                </strong>
            </p>
            <p style="margin: 0 0 16px;">
                <?php
                echo $alreadyHasOne
                    ? esc_html__('A second device - your phone as well as your laptop - means losing one does not lock you out.', 'fluent-security')
                    : esc_html__('Use your fingerprint, face or screen lock. Nothing to install, and nothing to type.', 'fluent-security');
                ?>
            </p>

            <p class="submit">
                <input type="button" id="fls_setup_passkey_start"
                       class="button button-large <?php echo $alreadyHasOne ? 'button-secondary' : 'button-primary'; ?>"
                       style="width: 100%;"
                       value="<?php
                       echo $alreadyHasOne
                           ? esc_attr__('Add another passkey', 'fluent-security')
                           : esc_attr__('Set up a passkey', 'fluent-security');
                       ?>"/>
            </p>
            <p id="fls_setup_passkey_status" style="clear: both;margin: 0;padding-top: 4px;font-size: 12px;color: #646970;min-height: 16px;"></p>

            <?php if ($hasAppPane) : ?>
                <p style="margin: 16px 0 0;text-align: center;">
                    <a href="#" id="fls_setup_show_app">
                        <?php esc_html_e('Use an authenticator app instead', 'fluent-security'); ?>
                    </a>
                </p>
            <?php endif; ?>

            <?php if (!$hasAppPane && $this->wasOffered()) : ?>
                <p style="margin: 16px 0 0;text-align: center;">
                    <a href="<?php echo esc_url($this->getRedirectTo()); ?>">
                        <?php esc_html_e('Not now', 'fluent-security'); ?>
                    </a>
                </p>
            <?php endif; ?>
        </div>

        <?php
        /*
         * Data only - see PasskeyTwoFaMethod::renderForm(). The behaviour is in
         * src/public/login_helper.js, which is also what the login flow's own enrollment
         * step runs.
         */
        ?>
        <script type="application/json" id="fls_setup_passkey_config"><?php
            echo wp_json_encode([
                'options'  => $options,
                'messages' => [
                    'prompting'   => __('Waiting for your passkey…', 'fluent-security'),
                    /*
                     * Two versions, because one of them is a lie on a screen where the
                     * app is switched off - there is nothing to fall back to and the link
                     * that would say so is not rendered either.
                     */
                    'cancelled'   => $hasAppPane
                        ? __('That was cancelled. You can try again, or use an authenticator app.', 'fluent-security')
                        : __('That was cancelled. You can try again.', 'fluent-security'),
                    'saving'      => __('Saving your passkey…', 'fluent-security'),
                    /*
                     * Only ever shown where the passkey is the whole screen. Everywhere
                     * else a browser that cannot make one is simply left on the app, and
                     * saying anything would be noise.
                     */
                    'unsupported' => __('This browser cannot set up a passkey. Try another browser, or a device with Touch ID, Windows Hello or a security key.', 'fluent-security')
                ]
            ]); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        ?></script>
        <?php
    }

    /**
     * Nothing this screen can offer, said without pretending otherwise.
     *
     * Three states end up here and they want different things said. An account that is
     * already set up is simply told so. An account with nothing to set up and nothing
     * owed is told that too, and sent on its way. The third is the one worth care: still
     * owed a factor, with every method that could satisfy it switched off. That should
     * not be reachable - DeviceRequirement::isRequiredForUser() asks
     * canBeSatisfiedBy() before it stands - so if it is, the site has been reconfigured
     * underneath the user and the only honest instruction is to ask somebody who can
     * change it.
     *
     * @param $user \WP_User
     * @param $secretFailed bool the app was on offer and the server could not make a secret
     * @return void
     */
    private function renderNothingToSetUp($user, $secretFailed = false)
    {
        if (TotpTwoFaMethod::isEnrolled($user)) {
            $this->renderEnrolled();

            return;
        }

        if ($secretFailed) {
            ?>
            <p style="margin: 0;color:#b32d2e;">
                <?php esc_html_e('A secret could not be generated on this server, so an authenticator app cannot be set up. Please contact your host.', 'fluent-security'); ?>
            </p>
            <?php

            return;
        }

        if (DeviceRequirement::isOwedBy($user)) {
            ?>
            <p style="margin: 0;color:#b32d2e;">
                <strong><?php esc_html_e('A second factor is required for your account, and none can be set up.', 'fluent-security'); ?></strong>
            </p>
            <p style="margin: 8px 0 0;">
                <?php esc_html_e('Please ask a site administrator to switch on passkeys or the authenticator app.', 'fluent-security'); ?>
            </p>
            <?php

            return;
        }

        ?>
        <p style="margin: 0;">
            <?php esc_html_e('There is no second factor to set up on this account.', 'fluent-security'); ?>
        </p>
        <?php

        $this->renderExit();
    }

    /**
     * @param $user \WP_User
     * @param $secret string the pending secret, already known to be non-empty
     * @param $hasPasskeyPane bool whether a passkey offer is on the page to switch to
     * @return void
     */
    private function renderSetup($user, $secret, $hasPasskeyPane = false)
    {
        $uri = TotpProvider::getProvisioningUri($secret, $user->user_login, get_bloginfo('name'));

        /*
         * Drawn here rather than by a chart service, because the URI contains the shared
         * secret: handing it to a third party to render would hand over the second
         * factor along with it.
         */
        $qr = QrCode::svg($uri, [
            'size'  => 200,
            'label' => __('QR code for setting up your authenticator app', 'fluent-security')
        ]);

        ?>
        <div id="fls_setup_app">
        <?php if ($hasPasskeyPane) : ?>
            <p style="margin: 0 0 16px;">
                <strong><?php esc_html_e('Use an authenticator app', 'fluent-security'); ?></strong>
            </p>
        <?php endif; ?>

        <p style="margin: 0 0 16px;">
            <?php esc_html_e('Scan this with an authenticator app, then enter the code it shows to confirm the two are paired.', 'fluent-security'); ?>
        </p>

        <?php if ($qr) : ?>
            <div style="text-align: center;margin-bottom: 16px;">
                <span style="display:inline-block;padding:10px;background:#fff;border:1px solid #c3c4c7;">
                    <?php echo $qr; // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from integers, the label is escaped ?>
                </span>
            </div>
        <?php endif; ?>

        <p style="margin: 0 0 4px;"><strong><?php esc_html_e('Setup key', 'fluent-security'); ?></strong></p>
        <!--
            Not an input: the key is longer than a phone-width field, and a field crops
            what will not fit rather than wrapping it - which leaves people typing in
            half a key. It is nothing the form submits either, so it need not be a field.
        -->
        <div id="fls_totp_secret_display"><?php echo esc_html(trim(chunk_split($secret, 4, ' '))); ?></div>
        <p style="margin: 0 0 20px;font-size: 12px;color: #646970;">
            <?php esc_html_e('Cannot scan the code? Choose "enter a setup key" in your app and paste this in. Spaces do not matter.', 'fluent-security'); ?>
        </p>

        <label for="fls_totp_confirm_code"><?php esc_html_e('Code from your app', 'fluent-security'); ?></label>
        <input type="text" name="fls_totp_confirm_code" id="fls_totp_confirm_code" class="input"
               inputmode="numeric" autocomplete="off" placeholder="000000"
               style="font-size: 14px;letter-spacing: 3px;"/>
        <p style="margin: 4px 0 20px;font-size: 12px;color: #646970;">
            <?php esc_html_e('Nothing changes until you enter a code and finish.', 'fluent-security'); ?>
        </p>

        <!--
            The login page's own submit markup rather than a button styled by hand. It is
            what the login page designer colours, so on a site that has set its brand
            colours this button is the same button as the one on the login form - and on
            a site that has not, it is WordPress's.
        -->
        <p class="submit">
            <input type="submit" id="fls_totp_submit" class="button button-primary button-large"
                   value="<?php esc_attr_e('Finish setup', 'fluent-security'); ?>"/>
        </p>

        <?php if ($hasPasskeyPane) : ?>
            <!--
                Hidden until the script has confirmed the browser can actually create a
                passkey. A link back to an offer the platform will refuse is worse than no
                link - see initSetupPasskey() in login_helper.js.
            -->
            <p style="clear: both;margin: 0;padding-top: 12px;text-align: center;display: none;"
               id="fls_setup_show_passkey_wrap">
                <a href="#" id="fls_setup_show_passkey">
                    <?php esc_html_e('Use a passkey instead', 'fluent-security'); ?>
                </a>
            </p>
        <?php endif; ?>

        <?php if ($this->wasOffered()) : ?>
            <!--
                A real way out, said plainly. An offer with no way to decline is not an
                offer, and a decline hidden behind the back button is the same thing.
            -->
            <p style="clear: both;margin: 0;padding-top: 12px;text-align: center;">
                <a href="<?php echo esc_url($this->getRedirectTo()); ?>" id="fls_totp_skip">
                    <?php esc_html_e('Not now', 'fluent-security'); ?>
                </a>
            </p>
        <?php endif; ?>
        </div>
        <?php
    }

    /**
     * @return void
     */
    private function renderEnrolled()
    {
        ?>
        <p style="margin: 0;">
            <strong style="color:#00a32a;">&#10003; <?php esc_html_e('Your authenticator app is set up.', 'fluent-security'); ?></strong>
        </p>
        <p style="margin: 8px 0 0;font-size: 12px;color: #646970;">
            <?php esc_html_e('You will be asked for a code from it the next time you sign in.', 'fluent-security'); ?>
        </p>
        <?php

        $this->renderExit();
    }

    /**
     * The way off this screen. It is reached by being sent here, so leaving it has to be
     * something other than the back button.
     *
     * @param $primary bool whether leaving is now the thing to do next
     * @return void
     */
    private function renderExit($primary = false)
    {
        /*
         * A button rather than a link where the user has just finished: they came here to
         * get somewhere else, the requirement is met, and the only remaining offer on the
         * screen - another passkey - is optional. A plain link under a coloured button
         * makes the optional thing look like the next step.
         */
        if ($primary) {
            ?>
            <p class="submit" style="margin: 20px 0 0;">
                <a href="<?php echo esc_url($this->getRedirectTo()); ?>"
                   class="button button-primary button-large" style="width: 100%;text-align: center;">
                    <?php esc_html_e('Continue', 'fluent-security'); ?> &rarr;
                </a>
            </p>
            <?php

            return;
        }

        ?>
        <p style="margin: 20px 0 0;">
            <a href="<?php echo esc_url($this->getRedirectTo()); ?>">
                <?php esc_html_e('Continue', 'fluent-security'); ?> &rarr;
            </a>
        </p>
        <?php
    }

    /**
     * @param $notice array
     * @return void
     */
    private function renderNotice($notice)
    {
        $type = Arr::get($notice, 'type');
        $codes = (array)Arr::get($notice, 'codes', []);

        $colors = [
            'error' => '#b32d2e',
            'codes' => '#00a32a',
            'info'  => '#72aee6'
        ];

        $border = isset($colors[$type]) ? $colors[$type] : $colors['info'];

        ?>
        <div style="border-left: 4px solid <?php echo esc_attr($border); ?>;background:#f6f7f7;padding: 10px 14px;margin: 0 0 20px;">
            <p style="margin: 0;"><?php echo esc_html(Arr::get($notice, 'message')); ?></p>
            <?php if ($codes) : ?>
                <p style="margin: 12px 0 4px;">
                    <textarea readonly rows="<?php echo (int)count($codes); ?>" onclick="this.select();"
                              style="width: 100%;font-family: Menlo, Consolas, monospace;letter-spacing: 2px;"><?php echo esc_textarea(implode("\n", $codes)); ?></textarea>
                </p>
                <p style="margin: 0;font-size: 12px;color: #646970;">
                    <?php
                    /*
                     * "Your second factor", because this notice now carries the codes for a
                     * passkey too - and telling somebody who has just used Touch ID to keep
                     * the codes away from their authenticator app names a thing they do not
                     * have. The instruction is the same either way: not on the device.
                     */
                    esc_html_e('Each code works once. Store them somewhere other than the device that holds your second factor.', 'fluent-security');
                    ?>
                </p>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Where the user came from, if they were sent here, and the front page otherwise -
     * never the admin area, which is the one place the audience for this screen cannot
     * go.
     *
     * @return string
     */
    private function getRedirectTo()
    {
        $requested = (string)Arr::get($_REQUEST, 'redirect_to', '');

        if (!$requested) {
            return home_url();
        }

        return wp_validate_redirect(esc_url_raw(urldecode($requested)), home_url());
    }
}
