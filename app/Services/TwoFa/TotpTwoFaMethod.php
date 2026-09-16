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
     * Recovery codes live on the account rather than here - see RecoveryCodes. They
     * used to be part of this method's own record, which is why a user with only
     * passkeys had nothing to fall back on.
     */
    const RECOVERY_CODE_COUNT = RecoveryCodes::CODE_COUNT;

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

        /*
         * Asked before anything else now, so that it vetoes both routes below. A site
         * that says this user may not have an authenticator app means it whether the app
         * was offered to them or demanded of them.
         */
        if (!apply_filters('fluent_auth/totp_enabled', true, $user)) {
            return false;
        }

        /*
         * Requiring a second factor grants the methods that can satisfy it. An owner who
         * says "these roles must hold a second factor" has already said those roles may
         * set one up; making them also tick the allow list is a way for the requirement
         * to be switched on and quietly do nothing, which is the worst outcome available
         * to a security setting.
         *
         * This is also what makes DeviceRequirement's anti-lockout guard unnecessary:
         * an app needs nothing from the site, so a required user can always reach one.
         */
        if (DeviceRequirement::isRequiredForUser($user)) {
            return true;
        }

        if (Helper::getSetting('totp_2fa') !== 'yes') {
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
        if (RecoveryCodes::looksLikeCode($normalised)) {
            return RecoveryCodes::consume($user, $normalised);
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
        $row = FactorStore::firstForUser($user, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);

        if ($row) {
            FactorStore::touch($row->id, $counter);
        }

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
     * The confirmed secret, or an empty string if setup was never finished.
     *
     * A row that is still `pending` deliberately does not answer here. That distinction
     * is what keeps somebody who opened the setup page once and walked away from
     * counting as enrolled - and it is now a status the database can filter on rather
     * than the absence of a second meta key.
     *
     * @param $user \WP_User|int
     * @return string
     */
    public static function getSecret($user)
    {
        $row = FactorStore::firstForUser($user, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);

        /*
         * Nothing in the table, but this user may predate it. Moved on the way past
         * rather than left for the batch, because the alternative is not a lockout - it
         * is this account quietly ceasing to be asked for a second factor, which nobody
         * would report. The check costs one cached meta read and stops entirely once
         * the batch has confirmed there is nothing left to find.
         */
        if (!$row && FactorMigration::isPending()) {
            $userId = self::resolveUserId($user);

            if ($userId && FactorMigration::migrateUser($userId)) {
                $row = FactorStore::firstForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);
            }
        }

        if (!$row) {
            return '';
        }

        $secret = (string)$row->secret;

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

        if (!FactorStore::ensureTable()) {
            return false;
        }

        /*
         * The live row is replaced rather than added to - an account has one
         * authenticator app, and a second would mean getSecret() answering with
         * whichever happened to be first. The pending row goes too, since this is what
         * it was waiting to become.
         */
        FactorStore::deleteForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);
        FactorStore::deleteForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING);

        $stored = FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'status'  => FactorStore::STATUS_ACTIVE,
            'secret'  => $secret,
            'counter' => (int)$counter,
            'label'   => __('Authenticator app', 'fluent-security')
        ]);

        if (is_wp_error($stored)) {
            return false;
        }

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

        FactorStore::deleteForUser($userId, FactorStore::TYPE_TOTP);

        /*
         * Recovery codes outlive this method only if something else can still use them.
         * Where the authenticator app was the account\'s only factor, codes left behind
         * would be a way in that nobody is watching and that the user believes they
         * turned off.
         */
        if (!PasskeyTwoFaMethod::isEnrolled($userId)) {
            RecoveryCodes::clear($userId);
        }

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

        $pending = self::getPendingSecret($userId);

        if ($pending) {
            return $pending;
        }

        $pending = TotpProvider::generateSecret();

        if (!$pending || !FactorStore::ensureTable()) {
            return '';
        }

        /*
         * Only the abandoned attempt goes. An account that is already enrolled may open
         * the setup screen again - to re-pair a replacement phone - and the secret it is
         * still signing in with has to survive that until a new one is confirmed.
         */
        FactorStore::deleteForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING);

        $stored = FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'status'  => FactorStore::STATUS_PENDING,
            'secret'  => $pending
        ]);

        return is_wp_error($stored) ? '' : $pending;
    }

    /**
     * Throws away any half-finished setup and starts a new one.
     *
     * The difference from getOrCreatePendingSecret() matters wherever the setup screen
     * can be reached by somebody who only knows the password. That screen shows the
     * secret, and a pending secret has no expiry - so an attacker who signs in, reads
     * it and walks away leaves it sitting there for the real account holder to be
     * handed, scan and activate. Both then hold the same authenticator, the site
     * reports the account as protected, and nothing on either side ever says otherwise.
     *
     * Reusing a pending secret is right on the profile screen, where the only person
     * who can reach it is already signed in. It is wrong at the login gate, so that
     * caller asks for this instead and every attempt starts its own.
     *
     * @param $user \WP_User|int
     * @return string
     */
    public static function regeneratePendingSecret($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId) {
            return '';
        }

        FactorStore::deleteForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING);

        return self::getOrCreatePendingSecret($userId);
    }

    /**
     * @param $user \WP_User|int
     * @return string
     */
    public static function getPendingSecret($user)
    {
        $row = FactorStore::firstForUser($user, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING);

        if (!$row) {
            return '';
        }

        $secret = (string)$row->secret;

        return TotpProvider::isValidSecret($secret) ? $secret : '';
    }

    /**
     * When the authenticator app was paired, as a mysql datetime.
     *
     * @param $user \WP_User|int
     * @return string empty if it never was
     */
    public static function getActivatedAt($user)
    {
        $row = FactorStore::firstForUser($user, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);

        return $row ? (string)$row->created_at : '';
    }

    /**
     * Issues a fresh set of recovery codes.
     *
     * Kept here as well as on RecoveryCodes because the setup screen calls it by this
     * name, and because generating them is part of finishing an enrollment rather than
     * something a user does on its own.
     *
     * @param $user \WP_User|int
     * @return array the plaintext codes, to display once
     */
    public static function generateRecoveryCodes($user)
    {
        return RecoveryCodes::generate($user);
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    public static function getRemainingRecoveryCount($user)
    {
        return RecoveryCodes::countRemaining($user);
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    private static function getLastCounter($user)
    {
        $row = FactorStore::firstForUser($user, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);

        return $row ? (int)$row->counter : 0;
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
}
