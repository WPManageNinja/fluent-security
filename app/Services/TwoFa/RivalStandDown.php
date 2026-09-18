<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * Ask the other second factor to stand down, for the one moment it would break the login.
 *
 * The problem this solves is in TwoFaConflictCheck: completing a verified challenge means
 * signing the user in for real, which fires `wp_login`, and a rival second factor listening
 * there throws the session away and renders its own form into our verification request. The
 * user loops. Several of these plugins publish a filter for exactly this situation, so where
 * one exists the loop can simply not happen.
 *
 * WHEN THIS IS ALLOWED TO RUN IS THE WHOLE DESIGN. It is switched on around one call -
 * the wp_signon() that completes a challenge this plugin has already verified - and off
 * again immediately after. By then the user has produced a second factor; standing the other
 * one down removes a duplicate, not a factor. Every other login on the site is untouched,
 * including one where our own second factor did not apply, so a site whose policy is really
 * being enforced by the other plugin keeps being enforced by it.
 *
 * That scoping is what makes this safe rather than presumptuous, and it is why the filters
 * are added and removed here rather than registered at boot. A stand-down left attached would
 * be this plugin quietly switching off somebody else's security control for the whole
 * request, which is not a thing to do by accident.
 *
 * Only three of the plugins TwoFaConflictCheck knows about can be asked. The rest have no
 * hook, or have one that does not mean what its name suggests - SiteGround's
 * `sg_security_2fa_do_not_challenge` gates whether a remember-this-device cookie is honoured,
 * so returning false there would *force* a challenge rather than skip one. For those the
 * conflict is real and the check still reports it as something to fix.
 */
class RivalStandDown
{
    /**
     * Filters currently attached, so resume() removes exactly what standDown() added and
     * nothing else - including on a site where somebody has already filtered the same hook
     * for their own reasons.
     *
     * @var array
     */
    protected static $attached = [];

    /**
     * The plugins that can be asked, and what answer means "not this login".
     *
     * `rival` ties each one to its entry in TwoFaConflictCheck, so the check can say which
     * conflicts this plugin defuses and which it can only report.
     *
     * Every value here was read from the plugin's own source and the direction confirmed at
     * the call site, because two of the candidates that did not make this list read as
     * suppression hooks by name and do the opposite.
     *
     * @return array
     */
    public static function handlers()
    {
        $handlers = [
            /*
             * Empties the provider list for this user. `is_user_using_two_factor()` asks for
             * a primary provider, gets nothing, and the login proceeds - which is the same
             * path a user with no second factor configured takes.
             */
            'two_factor' => [
                'rival'  => 'two-factor/two-factor.php',
                'filter' => 'two_factor_enabled_providers_for_user',
                'value'  => []
            ],
            /*
             * `is_auth_enable_for()` returns false for this user without consulting roles.
             */
            'defender' => [
                'rival'  => 'defender-security/wp-defender.php',
                'filter' => 'wp_defender_2fa_user_enabled',
                'value'  => false
            ],
            /*
             * The interstitial is the screen it would have put in front of the login.
             */
            'solid_security' => [
                'rival'  => 'better-wp-security/better-wp-security.php',
                'filter' => 'itsec_two_factor_interstitial_show_to_user',
                'value'  => false
            ]
        ];

        return (array)apply_filters('fluent_auth/2fa_stand_down_handlers', $handlers);
    }

    /**
     * Whether standing rivals down is wanted on this site at all.
     *
     * On by default: the alternative is a login that cannot be completed, and a site with
     * both plugins switched on has not chosen that. Off is for a site that would rather the
     * other plugin kept running and will turn ours off instead - which the conflict check
     * has been telling them to do either way.
     *
     * @return bool
     */
    public static function isEnabled()
    {
        return (bool)apply_filters('fluent_auth/stand_down_rival_2fa', true);
    }

    /**
     * The rivals whose conflict this plugin can defuse, as plugin paths.
     *
     * Read by the conflict check so it can word those differently from the ones it can only
     * report. Not a claim that the plugin is installed - just that if it is, there is a hook.
     *
     * @return array
     */
    public static function handledRivals()
    {
        if (!self::isEnabled()) {
            return [];
        }

        $rivals = [];

        foreach (self::handlers() as $handler) {
            if (!empty($handler['rival'])) {
                $rivals[] = $handler['rival'];
            }
        }

        return $rivals;
    }

    /**
     * Attach the stand-downs. Call resume() in a finally.
     *
     * Late priority so this is the last word, and a closure per handler so the value each
     * one returns is fixed here rather than read again while the rival is mid-decision.
     *
     * @return void
     */
    public static function standDown()
    {
        if (self::$attached || !self::isEnabled()) {
            return;
        }

        foreach (self::handlers() as $id => $handler) {
            if (empty($handler['filter']) || !array_key_exists('value', $handler)) {
                continue;
            }

            $value = $handler['value'];

            $callback = function () use ($value) {
                return $value;
            };

            /*
             * PHP_INT_MAX rather than a merely high number: these hooks exist so a site can
             * make this decision, and if the site has its own opinion on the same filter the
             * one that runs last is the one the rival acts on. Ours has to be it, for the
             * length of a call that would otherwise fail outright.
             */
            add_filter($handler['filter'], $callback, PHP_INT_MAX, 1);

            self::$attached[] = [$handler['filter'], $callback];
        }
    }

    /**
     * Detach every stand-down this class attached.
     *
     * Removing by the stored callback rather than by filter name, so a site that had its own
     * callback on the same hook still has it afterwards. Always paired with standDown() in a
     * finally: leaving one of these attached would silently switch off another plugin's
     * second factor for the rest of the request.
     *
     * @return void
     */
    public static function resume()
    {
        foreach (self::$attached as $attachment) {
            list($filter, $callback) = $attachment;
            remove_filter($filter, $callback, PHP_INT_MAX);
        }

        self::$attached = [];
    }
}
