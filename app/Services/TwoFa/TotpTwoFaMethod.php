<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

/**
 * A code from an authenticator app.
 *
 * This proves a device, which neither a mailbox nor an identity provider ever does, so
 * once a user has enrolled it is asked for however they signed in - by password, by
 * magic link or through Google. That is the whole point of registering it: it is the
 * one factor that a compromised inbox does not hand over. See AuthFactor.
 *
 * The secret lives in user meta rather than on the pending login row, so unlike an
 * emailed code there is nothing to issue at login time and nothing to send.
 */
class TotpTwoFaMethod extends BaseTwoFaMethod
{
    /**
     * The confirmed shared secret, base32. Its presence is what enrollment means.
     */
    const META_SECRET = '_fls_totp_secret';

    /**
     * A secret that has been shown to the user but not yet proven to have reached their
     * app. Kept apart from the real one so an abandoned setup never leaves an account
     * demanding codes from an authenticator that was never added.
     */
    const META_PENDING_SECRET = '_fls_totp_pending_secret';

    const META_ACTIVATED_AT = '_fls_totp_activated_at';

    /**
     * The last time step spent, so a code cannot be used twice.
     */
    const META_LAST_COUNTER = '_fls_totp_last_counter';

    /**
     * Hashes of the unused recovery codes.
     */
    const META_RECOVERY_CODES = '_fls_totp_recovery_codes';

    const RECOVERY_CODE_COUNT = 10;

    const RECOVERY_CODE_LENGTH = 10;

    /**
     * No I, O, 0 or 1: these codes get copied down by hand under stress, usually
     * because the phone that held the other factor is gone.
     */
    const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    public function getKey()
    {
        return 'totp';
    }

    public function getTitle()
    {
        return __('Authenticator App', 'fluent-security');
    }

    public function getSatisfiedFactor()
    {
        return AuthFactor::DEVICE;
    }

    public function getHandoffText()
    {
        return __('Enter the code from your authenticator app to finish signing in.', 'fluent-security');
    }

    public function getLoginMedia()
    {
        return 'two_factor_totp';
    }

    /**
     * Only for users who have actually enrolled.
     *
     * @param $user \WP_User
     * @return bool
     */
    public function isAvailableForUser($user)
    {
        return self::isAllowedForUser($user) && self::isEnrolled($user);
    }

    /**
     * Whether this user may set up an authenticator app at all.
     *
     * Separate from isAvailableForUser because enrollment has to be offered before
     * there is anything to be available - the profile screen asks this one.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    /**
     * Whether this method is in force for anybody at all.
     *
     * The site-wide half of isAllowedForUser, without a user to measure against. Asked
     * by screens that report on second factors rather than apply them - the enrollment
     * list has nothing to list if no method is live.
     *
     * @return bool
     */
    public static function isEnabledForAnyRole()
    {
        if (Helper::getSetting('totp_2fa') !== 'yes') {
            return false;
        }

        $roles = Helper::getSetting('totp_2fa_roles');

        return is_array($roles) && (bool)$roles;
    }

    public static function isAllowedForUser($user)
    {
        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        if (Helper::getSetting('totp_2fa') !== 'yes') {
            return false;
        }

        if (!apply_filters('fluent_auth/totp_enabled', true, $user)) {
            return false;
        }

        $roles = Helper::getSetting('totp_2fa_roles');

        /*
         * Naming the roles is how the method is turned on, so naming none turns it off.
         *
         * The other reading - that an empty list means every role - makes the switch
         * above enough to hand an authenticator app to every subscriber on the site the
         * moment it is flipped, which is not something to arrive at by leaving a field
         * alone. It is also the same shape as the required list underneath it, which has
         * always meant nobody when empty.
         */
        if (!$roles || !is_array($roles)) {
            return false;
        }

        return (bool)array_intersect($roles, array_values($user->roles));
    }

    /**
     * Whether this user has to have one before they can use the admin area.
     *
     * A role can only be required if it is also allowed, so that a policy can never
     * demand something the same screen refuses to let the user set up.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isRequiredForUser($user)
    {
        $user = self::resolveUser($user);

        if (!$user || !self::isAllowedForUser($user)) {
            return false;
        }

        $roles = Helper::getSetting('totp_required_roles');

        if (!$roles || !is_array($roles)) {
            return false;
        }

        return (bool)array_intersect($roles, array_values($user->roles));
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

    /**
     * Nothing to prepare: the proof is generated on the user's own device, and the
     * secret it comes from was agreed at enrollment.
     *
     * @param $user \WP_User
     * @return array
     */
    public function prepareChallenge($user)
    {
        return [
            'columns' => [],
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
        $submitted = sanitize_text_field((string)Arr::get($request, 'login_passcode'));
        $normalised = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $submitted));

        if ($normalised === '') {
            return new \WP_Error(
                'invalid_code',
                __('Please provide a valid login code', 'fluent-security')
            );
        }

        $secret = self::getSecret($user);

        if (!$secret) {
            return new \WP_Error(
                'totp_not_enrolled',
                __('Sorry, You can not use this verification method', 'fluent-security')
            );
        }

        // A recovery code is longer than a generated one, which is what tells them apart.
        if (strlen($normalised) === self::RECOVERY_CODE_LENGTH) {
            return self::consumeRecoveryCode($user, $normalised);
        }

        $counter = TotpProvider::verify($secret, $normalised, self::getLastCounter($user));

        if ($counter === false) {
            return false;
        }

        /*
         * Spend the step before reporting success. A code stays valid for its whole
         * drift window, so without this the same one works again for up to a minute and
         * a half - long enough for anyone who watched it being typed.
         */
        update_user_meta($user->ID, self::META_LAST_COUNTER, $counter);

        return true;
    }

    public function renderForm($data = [])
    {
        $redirectTo = Arr::get($data, 'redirect_to');

        if ($redirectTo) {
            $redirectTo = esc_url_raw($redirectTo);
        }

        ob_start();
        ?>
        <form
            style="margin-top: 20px;margin-left: 0;padding: 26px 24px 34px;font-weight: 400;overflow: hidden;background: #fff;border: 1px solid #c3c4c7;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);"
            class="fls_2fs" id="fls_2fa_form">
            <input type="hidden" name="login_hash" value="<?php echo esc_attr(Arr::get($data, 'login_hash')); ?>"/>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirectTo); ?>"/>
            <div class="user-pass-wrap">
                <p style="margin-bottom: 20px;"><?php esc_html_e('Open your authenticator app and enter the current code for this site.', 'fluent-security'); ?></p>
                <label for="login_passcode"><?php esc_html_e('Authentication Code', 'fluent-security'); ?></label>
                <div class="wp-pwd">
                    <input style="font-size: 14px;letter-spacing: 2px;"
                           placeholder="<?php esc_attr_e('Login Code', 'fluent-security'); ?>"
                           type="text"
                           inputmode="numeric"
                           autocomplete="one-time-code"
                           autofocus
                           name="login_passcode" id="login_passcode" class="input" size="20"/>
                </div>
                <p style="margin: 12px 0 20px;font-size: 12px;color: #646970;">
                    <?php esc_html_e('Lost your device? Enter one of your recovery codes instead.', 'fluent-security'); ?>
                </p>
                <div>
                    <button
                        style="display: block; cursor: pointer; width: 100%;border: 1px solid #2271b1;background: #2271b1;color: #fff;text-decoration: none;text-shadow: none;min-height: 32px;line-height: 2.30769231;padding: 4px 12px;font-size: 13px;border-radius: 3px;"
                        id="fls_2fa_confirm" type="submit">
                        <?php esc_html_e('Login', 'fluent-security'); ?>
                    </button>
                </div>
            </div>
        </form>
        <?php

        return ob_get_clean();
    }

    /**
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isEnrolled($user)
    {
        return (bool)self::getSecret($user);
    }

    /**
     * @param $user \WP_User|int
     * @return string
     */
    public static function getSecret($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return '';
        }

        $secret = (string)get_user_meta($userId, self::META_SECRET, true);

        return TotpProvider::isValidSecret($secret) ? $secret : '';
    }

    /**
     * Turns a proven pending secret into the live one.
     *
     * @param $user \WP_User|int
     * @param $secret string
     * @param $counter int the step the confirming code was generated for, spent so it
     *                     cannot immediately be replayed at the login form
     * @return bool
     */
    public static function activate($user, $secret, $counter = 0)
    {
        $userId = self::resolveUserId($user);

        if (!$userId || !TotpProvider::isValidSecret($secret)) {
            return false;
        }

        update_user_meta($userId, self::META_SECRET, $secret);
        update_user_meta($userId, self::META_ACTIVATED_AT, current_time('mysql'));
        update_user_meta($userId, self::META_LAST_COUNTER, (int)$counter);
        delete_user_meta($userId, self::META_PENDING_SECRET);

        do_action('fluent_auth/totp_activated', $userId);

        return true;
    }

    /**
     * @param $user \WP_User|int
     * @return void
     */
    public static function disable($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return;
        }

        delete_user_meta($userId, self::META_SECRET);
        delete_user_meta($userId, self::META_PENDING_SECRET);
        delete_user_meta($userId, self::META_ACTIVATED_AT);
        delete_user_meta($userId, self::META_LAST_COUNTER);
        delete_user_meta($userId, self::META_RECOVERY_CODES);

        do_action('fluent_auth/totp_disabled', $userId);
    }

    /**
     * The secret currently being set up, generating one if setup has just started.
     *
     * @param $user \WP_User|int
     * @return string
     */
    public static function getOrCreatePendingSecret($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return '';
        }

        $pending = (string)get_user_meta($userId, self::META_PENDING_SECRET, true);

        if (TotpProvider::isValidSecret($pending)) {
            return $pending;
        }

        $pending = TotpProvider::generateSecret();

        if (!$pending) {
            return '';
        }

        update_user_meta($userId, self::META_PENDING_SECRET, $pending);

        return $pending;
    }

    /**
     * @param $user \WP_User|int
     * @return string
     */
    public static function getPendingSecret($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return '';
        }

        $pending = (string)get_user_meta($userId, self::META_PENDING_SECRET, true);

        return TotpProvider::isValidSecret($pending) ? $pending : '';
    }

    /**
     * Issues a fresh set, replacing any that are left.
     *
     * Only the hashes are kept, so this is the one moment the codes can be shown. They
     * are hashed with a site salt rather than bcrypt because each one already carries
     * fifty bits of entropy - there is nothing to brute force - and a login has to be
     * able to check all ten without stalling.
     *
     * @param $user \WP_User|int
     * @return array the plaintext codes, to display once
     */
    public static function generateRecoveryCodes($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return [];
        }

        $codes = [];
        $hashes = [];

        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
            $code = '';

            for ($c = 0; $c < self::RECOVERY_CODE_LENGTH; $c++) {
                try {
                    $index = random_int(0, strlen(self::RECOVERY_ALPHABET) - 1);
                } catch (\Exception $e) {
                    return [];
                }

                $code .= self::RECOVERY_ALPHABET[$index];
            }

            $codes[] = $code;
            $hashes[] = self::hashRecoveryCode($code);
        }

        update_user_meta($userId, self::META_RECOVERY_CODES, $hashes);

        return $codes;
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    public static function getRemainingRecoveryCount($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return 0;
        }

        $hashes = get_user_meta($userId, self::META_RECOVERY_CODES, true);

        return is_array($hashes) ? count($hashes) : 0;
    }

    /**
     * Spends a recovery code if it matches an unused one.
     *
     * @param $user \WP_User|int
     * @param $code string already normalised
     * @return bool
     */
    private static function consumeRecoveryCode($user, $code)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return false;
        }

        $hashes = get_user_meta($userId, self::META_RECOVERY_CODES, true);

        if (!is_array($hashes) || !$hashes) {
            return false;
        }

        $candidate = self::hashRecoveryCode($code);
        $matched = false;
        $remaining = [];

        foreach ($hashes as $hash) {
            // Every entry is compared, so the time taken does not depend on which matched.
            if (hash_equals((string)$hash, $candidate) && !$matched) {
                $matched = true;
                continue;
            }

            $remaining[] = $hash;
        }

        if (!$matched) {
            return false;
        }

        update_user_meta($userId, self::META_RECOVERY_CODES, $remaining);

        do_action('fluent_auth/totp_recovery_code_used', $userId, count($remaining));

        return true;
    }

    /**
     * @param $code string
     * @return string
     */
    private static function hashRecoveryCode($code)
    {
        return hash_hmac('sha256', $code, wp_salt('secure_auth'));
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    private static function resolveUserId($user)
    {
        if ($user instanceof \WP_User) {
            return (int)$user->ID;
        }

        return is_numeric($user) ? (int)$user : 0;
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    private static function getLastCounter($user)
    {
        $userId = self::resolveUserId($user);

        return $userId ? (int)get_user_meta($userId, self::META_LAST_COUNTER, true) : 0;
    }
}
