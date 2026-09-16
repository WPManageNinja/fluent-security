<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\QrCode;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Setting up an authenticator app without going into wp-admin.
 *
 * The profile screen is still the natural home for this, but a site that keeps its
 * members out of the admin area has no way to send them there - so the same enrollment
 * is served from wp-login.php, which sits outside wp-admin, is reachable by any signed
 * in user whatever their role, and is already dressed by the login page designer.
 *
 * Setting one up is all this screen does. Turning an app off and drawing a fresh set of
 * recovery codes stay on the profile screen and in the admin enrollment list, so a page
 * anybody can reach cannot be used to weaken an account that is already protected.
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
     * Pairs the app, or says why it could not be paired.
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

        return [
            'type'    => 'codes',
            'message' => __('Your authenticator app is now set up. Save these recovery codes - they are the only way back in if you lose the device, and they are not shown again.', 'fluent-security'),
            'codes'   => TotpTwoFaMethod::generateRecoveryCodes($user->ID)
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

        login_header(__('Two-Factor Authentication', 'fluent-security'), '', null);

        ?>
        <form name="fls_totp_setup" id="fls_totp_setup" method="post"
              action="<?php echo esc_url(self::getUrl($this->getRedirectTo(), $this->wasOffered())); ?>"
              style="margin-top: 20px;margin-left: 0;padding: 26px 24px 34px;font-weight: 400;overflow: hidden;background: #fff;border: 1px solid #c3c4c7;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);">
            <?php
            wp_nonce_field(self::NONCE_ACTION, '_fls_totp_nonce');

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

            if (TotpTwoFaMethod::isEnrolled($user)) {
                $this->renderEnrolled();
            } elseif (!TotpTwoFaMethod::isAllowedForUser($user)) {
                /*
                 * Ordering matters: a role can be required to hold an app and then have
                 * that permission taken away, and being told to set up something the
                 * server will refuse to accept is worse than being told nothing.
                 */
                echo '<p style="margin: 0;">' . esc_html__('An authenticator app is not enabled for this account.', 'fluent-security') . '</p>';
                $this->renderExit();
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
                     */
                    ?>
                    <p style="margin: 0 0 20px;">
                        <?php esc_html_e('Your account is protected by its password. Adding an authenticator app means a code from your phone is needed too, so the password alone is not enough to sign in as you.', 'fluent-security'); ?>
                    </p>
                    <?php
                }

                $this->renderSetup($user);
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
     * @param $user \WP_User
     * @return void
     */
    private function renderSetup($user)
    {
        $secret = TotpTwoFaMethod::getOrCreatePendingSecret($user);

        if (!$secret) {
            echo '<p style="margin: 0;color:#b32d2e;">' . esc_html__('A secret could not be generated on this server, so an authenticator app cannot be set up. Please contact your host.', 'fluent-security') . '</p>';
            return;
        }

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
     * @return void
     */
    private function renderExit()
    {
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
                    <?php esc_html_e('Each code works once. Store them away from the device running your authenticator app.', 'fluent-security'); ?>
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
