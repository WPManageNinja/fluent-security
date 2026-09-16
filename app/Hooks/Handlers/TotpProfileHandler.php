<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\QrCode;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Enrollment for the authenticator app, on the WordPress profile screen.
 *
 * Setting one up is deliberately confined to a user's own profile. An administrator
 * can turn someone else's off - that is the recovery path when a phone is lost - but
 * never on, because doing so would mean pairing an authenticator the account holder
 * does not have and locking them out of their own account.
 */
class TotpProfileHandler
{
    const NONCE_ACTION = 'fls_totp_profile';

    /**
     * Recovery codes exist only as hashes once stored, so the one moment they can be
     * shown is between being generated and the page that reports it. A profile save
     * redirects, so they are carried across in a short lived transient and deleted the
     * first time they are rendered.
     */
    const NOTICE_TRANSIENT = 'fls_totp_notice_';

    public function register()
    {
        add_action('show_user_profile', [$this, 'renderSection']);
        add_action('edit_user_profile', [$this, 'renderSection']);
        add_action('personal_options_update', [$this, 'handleUpdate']);
        add_action('edit_user_profile_update', [$this, 'handleUpdate']);
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

        $isSelf = get_current_user_id() === (int)$user->ID;
        $isEnrolled = TotpTwoFaMethod::isEnrolled($user);
        $notice = self::pullNotice($user->ID);

        ?>
        <h2 id="fls-totp"><?php esc_html_e('Two-Factor Authentication', 'fluent-security'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php esc_html_e('Authenticator App', 'fluent-security'); ?></th>
                <td>
                    <?php
                    wp_nonce_field(self::NONCE_ACTION, '_fls_totp_nonce');

                    if ($notice) {
                        $this->renderNotice($notice);
                    }

                    if ($isEnrolled) {
                        $this->renderEnrolled($user, $isSelf);
                    } elseif (!TotpTwoFaMethod::isAllowedForUser($user)) {
                        echo '<p class="description">' . esc_html__('An authenticator app is not enabled for this account.', 'fluent-security') . '</p>';
                    } elseif ($isSelf) {
                        /*
                         * "Still owed", not "your role is required". They are different
                         * answers for the user who has met the requirement with a passkey
                         * and is here to add an app as well - telling that person they
                         * must do this is simply untrue.
                         */
                        if (DeviceRequirement::isOwedBy($user)) {
                            ?>
                            <div style="border-left: 4px solid #dba617;background:#fff;padding: 10px 14px;margin: 0 0 16px;box-shadow: 0 1px 1px rgba(0,0,0,.04);">
                                <p style="margin: 0;">
                                    <strong><?php esc_html_e('Required for your account.', 'fluent-security'); ?></strong>
                                    <?php esc_html_e('Set up a second factor - this app, or a passkey - to carry on signing in.', 'fluent-security'); ?>
                                </p>
                            </div>
                            <?php
                        }

                        $this->renderSetup($user);
                    } else {
                        echo '<p class="description">' . esc_html__('This user has not set up an authenticator app.', 'fluent-security') . '</p>';
                    }
                    ?>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * @param $user \WP_User
     * @param $isSelf bool
     * @return void
     */
    private function renderEnrolled($user, $isSelf)
    {
        $activatedAt = TotpTwoFaMethod::getActivatedAt($user);
        $remaining = TotpTwoFaMethod::getRemainingRecoveryCount($user);

        ?>
        <p>
            <strong style="color:#00a32a;">&#10003; <?php esc_html_e('Active', 'fluent-security'); ?></strong>
            <?php if ($activatedAt) : ?>
                <span class="description">
                    <?php
                    /* translators: %s: date the authenticator app was set up */
                    echo esc_html(sprintf(__('Set up on %s', 'fluent-security'), mysql2date(get_option('date_format'), $activatedAt)));
                    ?>
                </span>
            <?php endif; ?>
        </p>

        <?php if ($isSelf) : ?>
            <p class="description" style="margin-bottom: 8px;">
                <?php
                /* translators: %d: number of unused recovery codes */
                echo esc_html(sprintf(_n('%d unused recovery code remaining.', '%d unused recovery codes remaining.', $remaining, 'fluent-security'), $remaining));
                ?>
            </p>
            <?php if ($remaining < 3) : ?>
                <p class="description" style="color:#b32d2e;margin-bottom: 8px;">
                    <?php esc_html_e('You are running low. Generate a new set and store them somewhere other than the device holding your authenticator app.', 'fluent-security'); ?>
                </p>
            <?php endif; ?>
            <p>
                <label>
                    <input type="checkbox" name="fls_totp_regenerate_recovery" value="yes"/>
                    <?php esc_html_e('Generate a new set of recovery codes (this invalidates the old ones)', 'fluent-security'); ?>
                </label>
            </p>
        <?php endif; ?>

        <p>
            <label>
                <input type="checkbox" name="fls_totp_disable" value="yes"/>
                <?php
                if ($isSelf) {
                    esc_html_e('Turn off the authenticator app for my account', 'fluent-security');
                } else {
                    esc_html_e('Turn off the authenticator app for this user', 'fluent-security');
                }
                ?>
            </label>
        </p>
        <p class="description">
            <?php esc_html_e('Turning this off leaves the account protected by its password alone, unless another second factor is enabled.', 'fluent-security'); ?>
        </p>
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
            echo '<p class="description" style="color:#b32d2e;">' . esc_html__('A secret could not be generated on this server, so an authenticator app cannot be set up. Please contact your host.', 'fluent-security') . '</p>';
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
        <p><?php esc_html_e('Scan this with an authenticator app, then enter the code it shows to confirm the two are paired.', 'fluent-security'); ?></p>

        <?php if ($qr) : ?>
            <div style="display:inline-block;padding:10px;background:#fff;border:1px solid #c3c4c7;margin-bottom:16px;">
                <?php echo $qr; // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from integers, the label is escaped ?>
            </div>
            <p class="description" style="margin-bottom: 16px;">
                <?php esc_html_e('Cannot scan it? Use the setup key below instead.', 'fluent-security'); ?>
            </p>
        <?php endif; ?>

        <p style="margin-bottom: 4px;"><label for="fls_totp_secret_display"><strong><?php esc_html_e('Setup key', 'fluent-security'); ?></strong></label></p>
        <input type="text" id="fls_totp_secret_display" class="regular-text code" readonly
               onclick="this.select();"
               style="letter-spacing: 2px;"
               value="<?php echo esc_attr(trim(chunk_split($secret, 4, ' '))); ?>"/>
        <p class="description" style="margin-bottom: 16px;">
            <?php esc_html_e('Choose "enter a setup key" in your app and paste this in. Spaces do not matter.', 'fluent-security'); ?>
        </p>

        <p style="margin-bottom: 4px;"><label for="fls_totp_uri_display"><strong><?php esc_html_e('Or use this setup link', 'fluent-security'); ?></strong></label></p>
        <input type="text" id="fls_totp_uri_display" class="large-text code" readonly
               onclick="this.select();"
               value="<?php echo esc_attr($uri); ?>"/>
        <p class="description" style="margin-bottom: 16px;">
            <?php esc_html_e('Some password managers accept this link directly.', 'fluent-security'); ?>
        </p>

        <p style="margin-bottom: 4px;">
            <label for="fls_totp_confirm_code"><strong><?php esc_html_e('Code from your app', 'fluent-security'); ?></strong></label>
        </p>
        <input type="text" name="fls_totp_confirm_code" id="fls_totp_confirm_code" class="regular-text"
               inputmode="numeric" autocomplete="off" placeholder="000000" style="letter-spacing: 3px;"/>
        <p class="description">
            <?php esc_html_e('Save this page with the code filled in to finish. Nothing changes until you do.', 'fluent-security'); ?>
        </p>
        <?php
    }

    /**
     * @param $userId int
     * @return void
     */
    public function handleUpdate($userId)
    {
        $userId = (int)$userId;

        if (!$userId || !current_user_can('edit_user', $userId)) {
            return;
        }

        if (!wp_verify_nonce(sanitize_text_field(Arr::get($_POST, '_fls_totp_nonce', '')), self::NONCE_ACTION)) {
            return;
        }

        $isSelf = get_current_user_id() === $userId;

        if (Arr::get($_POST, 'fls_totp_disable') === 'yes') {
            TotpTwoFaMethod::disable($userId);
            self::setNotice($userId, 'info', __('The authenticator app has been turned off.', 'fluent-security'));
            return;
        }

        // Everything below pairs a device, which only the account holder can do.
        if (!$isSelf) {
            return;
        }

        /*
         * Any device factor, not this one. Recovery codes belong to the account rather
         * than to the authenticator app - see RecoveryCodes - and gating regeneration on
         * the app left a passkey-only holder with no way to replace a set they never saw.
         * That matters because hasFallback() counts those codes: the account reads as
         * recoverable on the strength of something nobody has.
         */
        if (Arr::get($_POST, 'fls_totp_regenerate_recovery') === 'yes' && DeviceRequirement::hasDeviceFactor($userId)) {
            $codes = TotpTwoFaMethod::generateRecoveryCodes($userId);
            self::setNotice($userId, 'codes', __('Your previous recovery codes no longer work. Here is the new set.', 'fluent-security'), $codes);
            return;
        }

        $submitted = sanitize_text_field((string)Arr::get($_POST, 'fls_totp_confirm_code', ''));

        if ($submitted === '' || TotpTwoFaMethod::isEnrolled($userId)) {
            return;
        }

        // The policy may have changed since the form was drawn.
        if (!TotpTwoFaMethod::isAllowedForUser($userId)) {
            return;
        }

        $pending = TotpTwoFaMethod::getPendingSecret($userId);

        if (!$pending) {
            self::setNotice($userId, 'error', __('That setup has expired. Reload this page to start again.', 'fluent-security'));
            return;
        }

        $counter = TotpProvider::verify($pending, $submitted);

        if ($counter === false) {
            self::setNotice($userId, 'error', __('That code did not match. Check your phone clock is set automatically, then try the current code.', 'fluent-security'));
            return;
        }

        /*
         * The confirming step is spent as part of activation, so the very code just
         * typed here cannot be turned around and replayed at the login form.
         */
        TotpTwoFaMethod::activate($userId, $pending, $counter);

        $codes = TotpTwoFaMethod::generateRecoveryCodes($userId);

        self::setNotice($userId, 'codes', __('Your authenticator app is now set up. Save these recovery codes - they are the only way back in if you lose the device, and they are not shown again.', 'fluent-security'), $codes);
    }

    /**
     * Shared with the front-end setup screen (see TotpSetupPageHandler) rather than
     * duplicated: it is one user being told one thing about their own enrollment, so
     * whichever screen they land on first should be the one that shows it.
     *
     * @param $userId int
     * @param $type string
     * @param $message string
     * @param $codes array
     * @return void
     */
    public static function setNotice($userId, $type, $message, $codes = [])
    {
        set_transient(self::NOTICE_TRANSIENT . $userId, [
            'type'    => $type,
            'message' => $message,
            'codes'   => $codes
        ], 5 * MINUTE_IN_SECONDS);
    }

    /**
     * @param $userId int
     * @return array|false
     */
    public static function pullNotice($userId)
    {
        $notice = get_transient(self::NOTICE_TRANSIENT . $userId);

        if (!$notice) {
            return false;
        }

        delete_transient(self::NOTICE_TRANSIENT . $userId);

        return is_array($notice) ? $notice : false;
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
        <div style="border-left: 4px solid <?php echo esc_attr($border); ?>;background:#fff;padding: 10px 14px;margin: 0 0 16px;box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <p style="margin: 0;"><?php echo esc_html(Arr::get($notice, 'message')); ?></p>
            <?php if ($codes) : ?>
                <p style="margin: 12px 0 4px;">
                    <textarea readonly rows="<?php echo (int)ceil(count($codes) / 2); ?>" class="code"
                              onclick="this.select();"
                              style="width: 100%;max-width: 420px;letter-spacing: 2px;"><?php echo esc_textarea(implode("\n", $codes)); ?></textarea>
                </p>
                <p class="description" style="margin: 0;">
                    <?php esc_html_e('Each code works once. Store them away from the device running your authenticator app.', 'fluent-security'); ?>
                </p>
            <?php endif; ?>
        </div>
        <?php
    }
}
