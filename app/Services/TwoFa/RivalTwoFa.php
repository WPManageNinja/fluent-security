<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Helper;

/**
 * Another plugin that also wants to finish the login.
 *
 * Two second factors on one site is not twice the security, it is a login that cannot be
 * completed. Not anybody's bug: a second factor lets the password through, holds the session
 * back, and hands it over once the proof arrives. This plugin hands it over by signing the
 * user in for real, which fires `wp_login` - and a rival listening there throws that session
 * away and puts its own form up instead, in the middle of our verification request.
 *
 * What the owner sees is a loop. The passkey prompt succeeds, the page returns to the login
 * screen, the prompt comes back. A recovery code behaves the same way and is spent on the way
 * past. Meanwhile `wp_login` really did fire, so the audit log records a success and the login
 * email goes out every time - the one signal they have says the logins are working.
 *
 * There is no way to coexist, and this plugin does not try. An earlier attempt asked the rival
 * to stand aside for the one request that completes a challenge; it was removed because it only
 * worked on two of the three plugins that publish a hook - Two Factor 0.16.0 has an explicit
 * anti-fail-open guard that forces its email provider back on - it also fired on the enrollment
 * path, where nothing has been proved yet, and it covered one of this plugin's four ways of
 * completing a login. What replaced it is this notice: say plainly that both cannot run, and let
 * the owner turn one off.
 *
 * Deliberately not a check and not on the findings list. That list is for things a site could
 * do better; this is a switch on the settings screen not working, and it belongs beside that
 * switch. See SettingsController::getSettings().
 */
class RivalTwoFa
{
    /**
     * What the settings screen needs to say, or null when there is nothing to say.
     *
     * Confirmed rivals only. A plugin that merely *has* a second factor somewhere we cannot
     * read is not worth a warning box on a settings screen - that would put a red panel in
     * front of every site with Wordfence installed, whether or not anybody uses its second
     * factor, and a warning that is usually wrong stops being read.
     *
     * @return array|null
     */
    public static function notice()
    {
        if (!self::ownSecondFactorIsOn()) {
            return null;
        }

        $rivals = array_values(array_filter(self::activeRivals(), function ($rival) {
            return !empty($rival['certain']);
        }));

        if (!$rivals) {
            return null;
        }

        return [
            'names' => self::names($rivals),
            /* Where to go and switch it off, in that plugin's own words for its own screens. */
            'where' => array_values(array_filter(array_map(function ($rival) {
                return (string)$rival['where'];
            }, $rivals))),
            'url'  => count($rivals) === 1 && !empty($rivals[0]['url'])
                ? admin_url($rivals[0]['url'])
                : admin_url('plugins.php')
        ];
    }

    /**
     * Whether this plugin is asking anybody for a second factor at all.
     *
     * The three settings are read directly rather than by asking the registered methods,
     * because a method contributed through `fluent_auth/2fa_methods` inherits an
     * isSwitchedOn() that answers true - which is the right default for enforcement and the
     * wrong one here, where it would invent a conflict on a site that has switched
     * everything off.
     *
     * @return bool
     */
    public static function ownSecondFactorIsOn()
    {
        foreach (['passkey_2fa', 'totp_2fa', 'email2fa'] as $setting) {
            if (Helper::getSetting($setting) === 'yes') {
                return true;
            }
        }

        return false;
    }

    /**
     * The known plugins: how to tell each one is here, and how to ask whether it is armed.
     *
     * Three things per entry, because they are three different questions.
     *
     * `constants` and `classes` are how presence is established. Preferred over the entry in
     * `active_plugins` because that names a *folder*: rename it, install the plugin as an
     * mu-plugin, or load it through a Composer autoloader, and the path stops matching while
     * the plugin carries on hooking `wp_login` exactly as before. A constant its main file
     * defines survives all three. `plugin` is kept as a fallback so a constant we have
     * guessed wrong costs detection rather than losing it entirely.
     *
     * `enabled` is the plugin's own answer to whether its second factor is switched on, and
     * it may say it does not know. Three outcomes, not two:
     *
     *   true  - it is on, and this is a conflict to fix today
     *   false - it is off, and there is nothing here to report at all
     *   null  - it will not say, so the reader is told to go and look
     *
     * Absent entirely means the plugin exists only to be a second factor, so being here is
     * the whole answer. Anything thrown is caught and read as null: a fatal inside somebody
     * else's settings getter must not take the security screen down with it.
     *
     * Note on the identifiers below. The constants, classes and getters are the published
     * shapes of plugins this build has no copy of, so they cannot be verified here - and an
     * identifier that is simply wrong is the most likely defect in this file. That is why
     * everything fails towards saying less: a wrong constant falls back to the plugin path,
     * a missing option reads as null rather than false, and a getter that errors reads as
     * null too. The failure is a check that goes quiet, never one that accuses a site of a
     * conflict it does not have.
     *
     * @return array
     */
    public static function knownRivals()
    {
        $rivals = [
            [
                'plugin'    => 'sg-security/sg-security.php',
                'name'      => __('Security Optimizer by SiteGround', 'fluent-security'),
                /* No constant: this plugin defines none. Its 2FA module class is the signal. */
                'classes'   => ['SG_Security\\Sg_2fa\\Sg_2fa'],
                'enabled'   => function () {
                    return self::optionSays('sg_security_sg2fa');
                },
                'where'     => __('Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=login-settings'
            ],
            [
                'plugin'    => 'two-factor/two-factor.php',
                'name'      => __('Two Factor', 'fluent-security'),
                'constants' => ['TWO_FACTOR_VERSION'],
                'classes'   => ['Two_Factor_Core'],
                /*
                 * Enrolment is per user here, so there is no site-wide switch to read. The
                 * person on this screen is the one user we can ask about without walking the
                 * whole user table, and a yes from them is a conflict they are living with
                 * right now. A no only means they have not enrolled, which says nothing about
                 * anybody else - hence null rather than false.
                 */
                'enabled'   => function () {
                    return self::pluginSays('Two_Factor_Core', 'is_user_using_two_factor', [get_current_user_id()])
                        ? true
                        : null;
                },
                'where'     => __('Users → Profile → Two-Factor Options', 'fluent-security'),
                'url'       => 'profile.php'
            ],
            [
                'plugin'    => 'wp-2fa/wp-2fa.php',
                'name'      => __('WP 2FA by Melapress', 'fluent-security'),
                'constants' => ['WP_2FA_VERSION'],
                'where'     => __('WP 2FA → Settings', 'fluent-security'),
                'url'       => 'admin.php?page=wp-2fa-policies'
            ],
            [
                'plugin'    => 'wordfence-login-security/wordfence-login-security.php',
                'name'      => __('Wordfence Login Security', 'fluent-security'),
                'constants' => ['WORDFENCE_LS_VERSION'],
                /*
                 * Verified on a real install: the full Wordfence plugin defines
                 * WORDFENCE_LS_VERSION as well, because it ships the same login-security
                 * code. Without this the one plugin is reported as two, naming a product the
                 * site has not got - and the row below already covers that case properly.
                 */
                'unless'    => ['WORDFENCE_VERSION'],
                /*
                 * Counted, not assumed. `active_count()` is the number of rows in their
                 * secrets table - which is to say the number of people who have actually
                 * finished setting a second factor up. One or more is a conflict happening
                 * now; none means the plugin is installed and nobody is using it yet, which
                 * is worth a look rather than a red row.
                 */
                'enabled'   => function () {
                    $enrolled = self::pluginObjectSays('WordfenceLS\\Controller_Users', 'shared', 'active_count');

                    return $enrolled === null ? null : ((int)$enrolled > 0 ? true : null);
                },
                'where'     => __('Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=WFLS'
            ],
            [
                'plugin'    => 'miniorange-2-factor-authentication/miniorange_2_factor_settings.php',
                'name'      => __('miniOrange 2-Factor Authentication', 'fluent-security'),
                'constants' => ['MO2F_VERSION'],
                'where'     => __('miniOrange 2-Factor → Two Factor', 'fluent-security'),
                'url'       => 'admin.php?page=miniOrange_2_factor_settings'
            ],
            [
                'plugin'    => 'two-factor-authentication/two-factor-login.php',
                'name'      => __('Two Factor Authentication', 'fluent-security'),
                /*
                 * `_Plugin`, never `Simba_Two_Factor_Authentication_1`. All-In-One Security
                 * bundles the same Simba library and defines that one too, so matching on it
                 * would report every AIOS site as running this plugin as well.
                 */
                'classes'   => ['Simba_Two_Factor_Authentication_Plugin'],
                /* The same per-role switch the library keeps wherever it is embedded. */
                'enabled'   => function () {
                    return self::optionSays('tfa_administrator');
                },
                'where'     => __('Users → Two Factor Authentication', 'fluent-security'),
                'url'       => 'profile.php'
            ],
            [
                'plugin'    => 'google-authenticator/google-authenticator.php',
                'name'      => __('Google Authenticator', 'fluent-security'),
                'classes'   => ['GoogleAuthenticator'],
                'where'     => __('Users → Profile → Google Authenticator Settings', 'fluent-security'),
                'url'       => 'profile.php'
            ],
            [
                'plugin'    => 'rublon/rublon2factor.php',
                'name'      => __('Rublon Multi-Factor Authentication', 'fluent-security'),
                'constants' => ['RUBLON2FACTOR_PLUGIN_PATH'],
                /* Not `Rublon`, which is the vendored SDK and says nothing about WordPress. */
                'classes'   => ['Rublon2FactorGUIWordPress'],
                'where'     => __('Rublon → Settings', 'fluent-security'),
                'url'       => 'admin.php?page=rublon'
            ],
            /*
             * Below here the second factor is one feature among many, so being installed is
             * not on its own a conflict - these have to be asked, and the ones that will not
             * answer stay a maybe.
             */
            [
                'plugin'    => 'wordfence/wordfence.php',
                'name'      => __('Wordfence Security', 'fluent-security'),
                'constants' => ['WORDFENCE_VERSION'],
                /*
                 * The full plugin ships the same login-security code, so the same count
                 * answers for it. Absence of those classes stays a maybe rather than a no:
                 * reading it as "switched off" would be a guess about their load order, and
                 * guessing wrong drops a real conflict silently.
                 */
                'enabled'   => function () {
                    $enrolled = self::pluginObjectSays('WordfenceLS\\Controller_Users', 'shared', 'active_count');

                    return $enrolled === null ? null : ((int)$enrolled > 0 ? true : null);
                },
                'where'     => __('Wordfence → Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=WFLS',
                'certain'   => false
            ],
            [
                'plugin'    => 'better-wp-security/better-wp-security.php',
                'name'      => __('Solid Security (formerly iThemes Security)', 'fluent-security'),
                'classes'   => ['ITSEC_Core'],
                /*
                 * This one publishes a module registry, so it can be asked properly rather
                 * than guessed at - the two-factor module being active is exactly the state
                 * that makes it a rival.
                 */
                'enabled'   => function () {
                    $active = self::pluginSays('ITSEC_Modules', 'is_active', ['two-factor']);

                    return $active === null ? null : (bool)$active;
                },
                'where'     => __('Security → Settings → Two-Factor', 'fluent-security'),
                'url'       => 'admin.php?page=itsec',
                'certain'   => false
            ],
            [
                'plugin'    => 'all-in-one-wp-security-and-firewall/wp-security.php',
                'name'      => __('All-In-One Security (AIOS)', 'fluent-security'),
                'classes'   => ['AIO_WP_Security_Simba_Two_Factor_Authentication_Plugin'],
                /*
                 * There is no `aiowps_` flag for this: the feature is the bundled Simba
                 * library, and the library keeps its own per-role switches. `tfa_administrator`
                 * is the one that matters, being the role this conflict is reported to.
                 * Absent means the library has not written its defaults yet, which is a look
                 * rather than a no - see optionSays().
                 */
                'enabled'   => function () {
                    return self::optionSays('tfa_administrator');
                },
                'where'     => __('WP Security → Two Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=aiowpsec',
                'certain'   => false
            ],
            [
                'plugin'    => 'wp-simple-firewall/icwp-wpsf.php',
                'name'      => __('Shield Security', 'fluent-security'),
                /*
                 * No constant to match on: this one boots through its own Composer
                 * autoloader and defines nothing global that is stable. The plugin path is
                 * all there is, which is exactly why the path fallback stays in isPresent().
                 */
                'classes'   => ['FernleafSystems\\Wordpress\\Plugin\\Shield\\Controller\\Controller'],
                /*
                 * Asked one provider at a time, because that is how they are switched on -
                 * there is no single "2FA is enabled" flag. Any provider on is a conflict;
                 * all of them off is genuinely nothing to report. The container is reached
                 * the way their own provider classes reach it.
                 */
                'enabled'   => function () {
                    $container = self::pluginSays(
                        'FernleafSystems\\Wordpress\\Plugin\\Shield\\Controller\\Controller',
                        'GetInstance'
                    );

                    if (!is_object($container) || !isset($container->opts) || !method_exists($container->opts, 'optIs')) {
                        return null;
                    }

                    foreach (['enable_google_authenticator', 'enable_email_authentication', 'enable_yubikey'] as $provider) {
                        if ($container->opts->optIs($provider, 'Y')) {
                            return true;
                        }
                    }

                    return false;
                },
                'where'     => __('Shield → Login Protection → Multi-Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=icwp-wpsf-plugin',
                'certain'   => false
            ],
            [
                'plugin'    => 'defender-security/wp-defender.php',
                'name'      => __('Defender Security', 'fluent-security'),
                'constants' => ['DEFENDER_VERSION'],
                'classes'   => ['WP_Defender\\Controller\\Two_Factor'],
                /*
                 * Their settings model hydrates itself and publishes the switch as a plain
                 * public property, so this is their own answer rather than our reading of
                 * their storage.
                 */
                'enabled'   => function () {
                    $on = self::pluginModelSays('WP_Defender\\Model\\Setting\\Two_Fa', 'enabled');

                    return $on === null ? null : (bool)$on;
                },
                'where'     => __('Defender → 2FA', 'fluent-security'),
                'url'       => 'admin.php?page=wdf-advanced-tools',
                'certain'   => false
            ]
        ];

        /*
         * Filtered so a site or an add-on can name one we have never heard of - and so a
         * site that has genuinely made two second factors coexist can take one off the list
         * rather than living with a red row it cannot answer.
         */
        return (array)apply_filters('fluent_auth/2fa_conflict_plugins', $rivals);
    }

    /*
     * The four readers below are public rather than protected. Nothing is protected by
     * hiding them - they hold no state and enforce no invariant - and they are the part of
     * this file most likely to be wrong, since every symbol they name belongs to a plugin
     * this build has no copy of. Reachable means testable.
     */

    /**
     * Call a method on a class this build does not ship, if it is there.
     *
     * The class name stays a string the whole way through. These are other people's symbols,
     * resolved at run time on sites that happen to have them, and writing them as literals
     * would have static analysis here reporting every one as a class that does not exist -
     * which is true of this repository and beside the point.
     *
     * Null for "not there", so a plugin that has renamed the method between versions reads as
     * one that will not answer rather than one that answered no.
     *
     * @param string $class
     * @param string $method
     * @param array $args
     * @return mixed|null
     */
    public static function pluginSays($class, $method, $args = [])
    {
        /*
         * Without the class already being loaded this is a question about a plugin that is not
         * there, and method_exists() would run the autoloader to answer it - pulling a rival's
         * Composer tree into a request that only wanted to know whether it was needed.
         * isPresent() passes false to class_exists() for the same reason.
         */
        if (!class_exists($class, false) || !method_exists($class, $method)) {
            return null;
        }

        return call_user_func_array([$class, $method], $args);
    }

    /**
     * Reach an object through a plugin's own accessor and call a method on it.
     *
     * Two hops, both guarded, because that is how these are published: a static `shared()`
     * or `GetInstance()` that hands back the live controller, and the question asked of that.
     * Null the moment either hop is not what this expects, which the caller reads as "will
     * not say".
     *
     * @param string $class
     * @param string $accessor
     * @param string $method
     * @param array $args
     * @return mixed|null
     */
    public static function pluginObjectSays($class, $accessor, $method, $args = [])
    {
        $object = self::pluginSays($class, $accessor);

        if (!is_object($object) || !method_exists($object, $method)) {
            return null;
        }

        return call_user_func_array([$object, $method], $args);
    }

    /**
     * Read a public property off a settings model the plugin expects to be constructed.
     *
     * Defender's settings are a model that hydrates itself on construction, so there is no
     * accessor to call - the object *is* the answer. Constructed inside the caller's
     * try/catch, since building one runs their code.
     *
     * @param string $class
     * @param string $property
     * @return mixed|null
     */
    public static function pluginModelSays($class, $property)
    {
        if (!class_exists($class, false)) {
            return null;
        }

        $model = new $class();

        if (!property_exists($model, $property)) {
            return null;
        }

        return $model->$property;
    }

    /**
     * What a stored flag says, distinguishing "off" from "not there".
     *
     * A missing option is the shape a wrong option name takes, and reading that as `false`
     * would drop the rival silently - the one failure that loses a real conflict rather than
     * softening it. Absent answers null instead, which lands the plugin in the list the
     * reader is asked to go and check.
     *
     * @param string $name
     * @return bool|null
     */
    public static function optionSays($name)
    {
        $value = get_option($name, null);

        if ($value === null) {
            return null;
        }

        return (bool)$value;
    }

    /**
     * @return array the entries that are here, each with `certain` resolved
     */
    public static function activeRivals()
    {
        $active = self::activePlugins();
        $found = [];

        foreach (self::knownRivals() as $rival) {
            /*
             * The list is filterable, so an entry can be anything at all. Filled in rather
             * than trusted: a missing name would otherwise reach the title of a red row on
             * somebody's dashboard as an empty string.
             */
            if (!is_array($rival)) {
                continue;
            }

            $rival = array_merge([
                'plugin'    => '',
                'name'      => '',
                'constants' => [],
                'classes'   => [],
                'unless'    => [],
                'where'     => '',
                'url'       => '',
                'certain'   => true
            ], $rival);

            if (!$rival['name'] || !self::isPresent($rival, $active)) {
                continue;
            }

            /*
             * No answer declared means the plugin is a second factor and nothing else, so
             * being here is the whole of it and `certain` stands as declared.
             */
            if (isset($rival['enabled'])) {
                $enabled = self::askPlugin($rival['enabled']);

                /* It says its second factor is off. There is no conflict to report. */
                if ($enabled === false) {
                    continue;
                }

                $rival['certain'] = $enabled === true;
            }

            $found[] = $rival;
        }

        return $found;
    }

    /**
     * Whether the plugin is running, by any of the three signals.
     *
     * A defined constant or a loaded class is the better evidence and is tried first: both
     * are facts about what this request has loaded, where the path in `active_plugins` is a
     * fact about a folder name. The path is still consulted, because a constant guessed wrong
     * should cost the accuracy of one entry rather than the whole detection.
     *
     * `class_exists` is asked not to autoload. Triggering somebody's autoloader to answer a
     * question about whether they are here is a side effect this has no business causing, and
     * on a Composer-backed plugin it would pull files in to prove they were not needed.
     *
     * @param array $rival
     * @param array $active plugin paths
     * @return bool
     */
    protected static function isPresent($rival, $active)
    {
        /*
         * Another entry owns this install. Two products can define the same constant when one
         * bundles the other, and the bundled one must not be named in its own right - the
         * site has not got it, and the entry for what it actually has says the same thing
         * with the right name on it.
         */
        foreach ((array)$rival['unless'] as $constant) {
            if (defined($constant)) {
                return false;
            }
        }

        foreach ((array)$rival['constants'] as $constant) {
            if (defined($constant)) {
                return true;
            }
        }

        foreach ((array)$rival['classes'] as $class) {
            if (class_exists($class, false)) {
                return true;
            }
        }

        return $rival['plugin'] && in_array($rival['plugin'], $active, true);
    }

    /**
     * Ask a plugin about its own settings, and survive whatever it does.
     *
     * This runs somebody else's code inside a request of ours. Their getter can throw, can
     * reach for a table that is mid-migration, or can fatal on a version whose signature we
     * guessed wrong - and the cost of that landing uncaught is the whole security screen, for
     * a question that was only ever asking how loudly to word one row.
     *
     * So everything that is not a definite answer becomes "it will not say", which the caller
     * reads as a maybe. \Throwable rather than \Exception because the interesting failures
     * here - a call to an undefined method, a wrong argument type - are Errors and would sail
     * straight past a catch on Exception.
     *
     * @param callable $ask
     * @return bool|null
     */
    protected static function askPlugin($ask)
    {
        if (!is_callable($ask)) {
            return null;
        }

        try {
            $answer = $ask();
        } catch (\Throwable $e) {
            return null;
        }

        return $answer === null ? null : (bool)$answer;
    }

    /**
     * Read from the option rather than through is_plugin_active(), which lives in a file
     * wp-admin loads and a REST request does not.
     *
     * @return array plugin files
     */
    protected static function activePlugins()
    {
        $active = get_option('active_plugins', []);
        $active = is_array($active) ? $active : [];

        if (is_multisite()) {
            $network = get_site_option('active_sitewide_plugins', []);

            if (is_array($network)) {
                $active = array_merge($active, array_keys($network));
            }
        }

        return array_values(array_unique($active));
    }

    /**
     * @param array $rivals
     * @return array
     */
    protected static function names($rivals)
    {
        return array_map(function ($rival) {
            return (string)$rival['name'];
        }, $rivals);
    }
}
