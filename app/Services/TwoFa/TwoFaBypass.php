<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * The way back in when the second factor cannot be answered.
 *
 * Every account with a second factor has a state where the honest owner is locked out:
 * the phone is lost, the authenticator was never transferred to the new one, the laptop
 * holding the only passkey is at the office, the browser will not do WebAuthn. Sites
 * without an answer to that get a support ticket, and the answer they are usually given
 * over email is "run this SQL" - which is worse than anything written here.
 *
 * So the answer is a constant in wp-config.php, and putting it there is itself the
 * authorisation. Somebody who can edit wp-config.php can already add an administrator,
 * change the database credentials or read the auth salts; a switch that only they can
 * reach gives away nothing they did not already hold. That is the whole security
 * argument, and it is why this can be explained openly on the login screen rather than
 * kept for support staff.
 *
 *     define('FLUENT_AUTH_DISABLE_TWO_FA', 'jane');   // just this account
 *     define('FLUENT_AUTH_DISABLE_TWO_FA', true);     // every account, site wide
 *
 * The named form is what the login screen offers, because it is no harder to paste and
 * it leaves the second factor standing for everybody else while one person gets back in.
 */
class TwoFaBypass
{
    const CONSTANT = 'FLUENT_AUTH_DISABLE_TWO_FA';

    /**
     * Whether the constant is present and asking for anything at all.
     *
     * @return bool
     */
    /**
     * What the site has asked for, if anything.
     *
     * Read through one accessor rather than touching the constant in three places. The
     * filter exists for two callers with the same problem: a test, which cannot define()
     * a constant without defining it for every test that follows in the process, and a
     * host that would rather drive this from a control panel than from a file. The
     * constant remains the supported path and the one the login screen describes.
     *
     * A filter that can switch off a second factor is only as dangerous as the code
     * already running inside WordPress, which could equally unhook the whole login flow.
     *
     * @return mixed null when nothing is set
     */
    public static function getConfiguredValue()
    {
        $value = defined(self::CONSTANT) ? constant(self::CONSTANT) : null;

        return apply_filters('fluent_auth/two_fa_bypass_value', $value);
    }

    /**
     * Whether the constant is present and asking for anything at all.
     *
     * @return bool
     */
    public static function isConfigured()
    {
        $value = self::getConfiguredValue();

        return $value === true || (is_string($value) && $value !== '') || (is_array($value) && $value);
    }

    /**
     * Whether it lifts the second factor for this particular user.
     *
     * @param $user \WP_User|int|null
     * @return bool
     */
    public static function isActiveFor($user)
    {
        if (!self::isConfigured()) {
            return false;
        }

        $value = self::getConfiguredValue();

        // Boolean true, and only boolean true, means everybody. A bare string is a name.
        if ($value === true) {
            return (bool)apply_filters('fluent_auth/two_fa_bypass_active', true, $user);
        }

        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        $names = is_array($value) ? $value : explode(',', (string)$value);

        foreach ($names as $name) {
            $name = trim((string)$name);

            if ($name === '') {
                continue;
            }

            /*
             * Login, email or id, because whoever is pasting this at two in the morning
             * should not also have to work out which one the site wants. Compared with
             * strcasecmp for the two that are case insensitive in WordPress itself.
             */
            if (strcasecmp($name, $user->user_login) === 0
                || strcasecmp($name, $user->user_email) === 0
                || (ctype_digit($name) && (int)$name === (int)$user->ID)) {
                return (bool)apply_filters('fluent_auth/two_fa_bypass_active', true, $user);
            }
        }

        return false;
    }

    /**
     * The line to paste, naming this account and no other.
     *
     * @param $user \WP_User
     * @return string
     */
    public static function getSuggestedLine($user)
    {
        $login = $user instanceof \WP_User ? $user->user_login : '';

        return sprintf("define('%s', '%s');", self::CONSTANT, addslashes($login));
    }

    /**
     * Who the constant currently covers, for the warning that asks for it to be removed.
     *
     * @return string
     */
    public static function describe()
    {
        if (!self::isConfigured()) {
            return '';
        }

        $value = self::getConfiguredValue();

        if ($value === true) {
            return __('every account on this site', 'fluent-security');
        }

        $names = is_array($value) ? $value : explode(',', (string)$value);
        $names = array_filter(array_map('trim', array_map('strval', $names)));

        return implode(', ', $names);
    }

    /**
     * How long the screen waits before admitting there is a way out, in seconds.
     *
     * Not zero, and the delay is the whole design. Offered immediately this reads as an
     * alternative to the second factor, and a proportion of people will take the easier
     * looking route every time - which is a security feature talked out of existence by
     * its own help text. Offered after somebody has been sitting on the form long enough
     * to have tried, it reads as what it is: the thing you need when the normal way has
     * failed.
     *
     * @return int
     */
    public static function getHelpDelay()
    {
        return (int)apply_filters('fluent_auth/lockout_help_delay', 20);
    }

    /**
     * Whether this screen should offer the way out to the person looking at it.
     *
     * Only to an account that could act on it. Somebody who cannot edit wp-config.php is
     * being shown a wall of instructions they cannot follow, in place of the one thing
     * that would help them, which is the address of whoever can.
     *
     * Showing it to an administrator gives nothing away. The reader has already typed
     * that account's password, and what they are being told is that a file they cannot
     * reach would let them in - true of the database credentials in the same file.
     *
     * @param $user \WP_User|false
     * @return bool
     */
    public static function shouldOfferHelp($user)
    {
        if (!$user instanceof \WP_User) {
            return false;
        }

        // Already lifted for them: there is nothing to instruct, they are simply in.
        if (self::isActiveFor($user)) {
            return false;
        }

        return (bool)apply_filters(
            'fluent_auth/show_lockout_help',
            user_can($user, 'manage_options'),
            $user
        );
    }

    /**
     * @param $user \WP_User|false
     * @return string
     */
    public static function renderHelp($user)
    {
        if (!self::shouldOfferHelp($user)) {
            return '';
        }

        $line = self::getSuggestedLine($user);
        $delay = self::getHelpDelay();

        ob_start();
        ?>
        <div id="fls_lockout_help" style="display: none;margin-top: 16px;padding: 14px 16px;background: #fff;border: 1px solid #c3c4c7;border-left: 4px solid #dba617;box-shadow: 0 1px 3px rgb(0 0 0 / 4%);">
            <p style="margin: 0 0 8px;">
                <strong><?php esc_html_e('Cannot complete this step?', 'fluent-security'); ?></strong>
            </p>
            <p style="margin: 0 0 10px;font-size: 13px;">
                <?php esc_html_e('Add this line to your wp-config.php, above the line that says "That\'s all, stop editing". It turns the second factor off for your account only, so you can sign in and fix it.', 'fluent-security'); ?>
            </p>
            <!--
                A field rather than a code block, because the point is to get these exact
                characters into another file. Selecting on focus is what makes that one
                gesture on a phone, which is often what somebody locked out is holding.
            -->
            <input type="text" readonly
                   value="<?php echo esc_attr($line); ?>"
                   onclick="this.select();"
                   style="width: 100%;font-family: Menlo, Consolas, monospace;font-size: 12px;padding: 6px;"/>
            <p style="margin: 10px 0 0;font-size: 12px;color: #646970;">
                <?php esc_html_e('Take the line out again once you are back in and your second factor is working. While it is there, this account is protected by its password alone, and every sign in it allows is recorded in the log.', 'fluent-security'); ?>
            </p>
        </div>
        <script>
            (function () {
                var help = document.getElementById('fls_lockout_help');

                if (!help) {
                    return;
                }

                window.setTimeout(function () {
                    help.style.display = '';
                }, <?php echo (int)($delay * 1000); ?>);
            })();
        </script>
        <?php

        return ob_get_clean();
    }

    /**
     * @param $user \WP_User|int|null
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

        $resolved = get_user_by('ID', (int)$user);

        return $resolved instanceof \WP_User ? $resolved : false;
    }
}
