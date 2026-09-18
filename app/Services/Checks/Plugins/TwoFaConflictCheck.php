<?php

namespace FluentAuth\App\Services\Checks\Plugins;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;

/**
 * Another plugin that also wants to be the one that finishes a login.
 *
 * Two second factors on one site is not twice the security, it is a login that cannot be
 * completed. The reason is structural rather than anybody's bug: a second factor works by
 * letting the password through, holding the session back, and handing it over only once the
 * proof arrives. This plugin completes that handover by signing the user in for real, which
 * fires `wp_login` - and a rival plugin listening there does what it was written to do, which
 * is to throw the session away and put its own form up instead. Its form is then rendered
 * into the middle of our verification request and the request ends there.
 *
 * What the site owner sees is a loop. The passkey prompt succeeds, the page returns to the
 * login screen, and the passkey prompt comes back. A recovery code behaves the same way and
 * is spent on the way past, so a user working through a printed list watches codes disappear
 * without ever getting in. Meanwhile `wp_login` really did fire, so the audit log records a
 * success and the login notification email goes out on every attempt - the one signal the
 * owner has says the logins are working.
 *
 * None of that is diagnosable from the symptoms, which is why it is worth a check. The rival
 * is doing nothing wrong and neither are we; the site simply has to pick one.
 *
 * Two findings rather than one, because they are two different decisions. A plugin whose
 * second factor we can see is switched on is something to turn off today. A plugin that
 * merely *has* a second factor among a dozen other features, whose setting lives somewhere we
 * cannot read, is something to go and look at. Saying both in the same red row would either
 * cry wolf about the second or undersell the first.
 */
class TwoFaConflictCheck extends Check
{
    const FINDING_ACTIVE = 'two_fa_conflict';

    const FINDING_POSSIBLE = 'two_fa_conflict_possible';

    public function id()
    {
        return 'two_fa_conflict';
    }

    public function group()
    {
        return 'plugins';
    }

    public function run()
    {
        /*
         * Nothing to clash over. A site running somebody else's second factor and none of
         * ours is not misconfigured - it has made a choice, and this check has no business
         * having an opinion about it.
         */
        if (!self::ownSecondFactorIsOn()) {
            return [];
        }

        $rivals = self::activeRivals();

        $confirmed = array_values(array_filter($rivals, function ($rival) {
            return !empty($rival['certain']);
        }));

        $possible = array_values(array_filter($rivals, function ($rival) {
            return empty($rival['certain']);
        }));

        /*
         * The all-clear is about the site, not about half of this check.
         *
         * It used to be emitted whenever the confirmed list came back empty, which is a
         * different question from whether anything was found - so a site running Wordfence
         * drew "No other plugin is competing to finish your logins" in green directly above
         * "Wordfence Security may be running two-factor authentication as well". Two rows
         * from one check, contradicting each other, and the green one is the one that reads
         * as the verdict.
         */
        if (!$confirmed && !$possible) {
            return [$this->settledFinding()];
        }

        return array_merge(
            $confirmed ? $this->confirmedFinding($confirmed) : [],
            $this->possibleFinding($possible)
        );
    }

    /**
     * Nothing found, by either half. The only state that earns a green row.
     *
     * @return Finding
     */
    protected function settledFinding()
    {
        return new Finding([
            'id'     => self::FINDING_ACTIVE,
            'check'  => $this->id(),
            'group'  => $this->group(),
            'state'  => Finding::STATE_PASSED,
            'title'  => __('No other plugin is competing to finish your logins', 'fluent-security'),
            'scored' => false
        ]);
    }

    /**
     * @param array $rivals
     * @return Finding[]
     */
    protected function confirmedFinding($rivals)
    {
        $names = self::names($rivals);

        if (Dismissals::has(self::FINDING_ACTIVE)) {
            return [new Finding([
                'id'     => self::FINDING_ACTIVE,
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => $this->confirmedTitle($names),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        return [new Finding([
            'id'       => self::FINDING_ACTIVE,
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_FIX,
            'title'    => $this->confirmedTitle($names),
            'why'      => __('Two plugins cannot both finish the same login. The other one throws away the session this plugin has just created, so passkeys, authenticator codes and recovery codes all end up back at the login screen - and a recovery code is spent each time it happens.', 'fluent-security'),
            'details'  => array_merge(
                self::describe($rivals),
                [
                    __('Turn off the second factor in one plugin or the other. Both protect the same logins, so whichever you keep loses you nothing.', 'fluent-security'),
                    __('Until then the audit log and the login notification emails will report each attempt as a success, because the other plugin does not step in until after the sign in has been recorded.', 'fluent-security')
                ]
            ),
            'action'   => 'navigate',
            'label'    => count($rivals) === 1 && !empty($rivals[0]['url'])
                ? __('Open its settings', 'fluent-security')
                : __('Open plugins', 'fluent-security'),
            'url'      => count($rivals) === 1 && !empty($rivals[0]['url'])
                ? admin_url($rivals[0]['url'])
                : admin_url('plugins.php'),
            'dismiss'  => 'ignore',
            'scored'   => false
        ])];
    }

    /**
     * @param array $rivals
     * @return Finding[]
     */
    protected function possibleFinding($rivals)
    {
        /*
         * No passed twin for this one. "We looked and found no plugin that might have a
         * second factor switched on somewhere we cannot read" is not a reassurance anybody
         * can act on, and the confirmed finding above already says the useful half.
         */
        if (!$rivals) {
            return [];
        }

        $names = self::names($rivals);

        if (Dismissals::has(self::FINDING_POSSIBLE)) {
            return [new Finding([
                'id'     => self::FINDING_POSSIBLE,
                'check'  => $this->id(),
                'group'  => $this->group(),
                'state'  => Finding::STATE_ACCEPTED,
                'title'  => $this->possibleTitle($names),
                'why'    => __('You have said this one is not for your site.', 'fluent-security'),
                'scored' => false
            ])];
        }

        return [new Finding([
            'id'       => self::FINDING_POSSIBLE,
            'check'    => $this->id(),
            'group'    => $this->group(),
            'state'    => Finding::STATE_OPEN,
            'severity' => Finding::SEVERITY_LOOK,
            'title'    => $this->possibleTitle($names),
            'why'      => __('These plugins can run a second factor of their own alongside everything else they do. This plugin cannot read whether that feature is switched on, so it is worth checking - if it is, your logins will loop instead of completing.', 'fluent-security'),
            'details'  => array_merge(
                self::describe($rivals),
                [__('If the feature is off, nothing is wrong and you can mark this as expected.', 'fluent-security')]
            ),
            'action'   => 'navigate',
            'label'    => __('Open plugins', 'fluent-security'),
            'url'      => admin_url('plugins.php'),
            'dismiss'  => 'ignore',
            'scored'   => false
        ])];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function accept($findingId)
    {
        if (!in_array($findingId, [self::FINDING_ACTIVE, self::FINDING_POSSIBLE], true)) {
            return new \WP_Error('unknown_check', __('That is not something this plugin knows how to check.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::add($findingId);

        return ['message' => __('Noted. This will not be mentioned again.', 'fluent-security')];
    }

    /**
     * @param string $findingId
     * @return array|\WP_Error
     */
    public function unaccept($findingId)
    {
        if (!in_array($findingId, [self::FINDING_ACTIVE, self::FINDING_POSSIBLE], true)) {
            return new \WP_Error('unknown_check', __('There is nothing to undo for this one.', 'fluent-security'), ['status' => 404]);
        }

        Dismissals::remove($findingId);

        return ['message' => __('This is back on the list.', 'fluent-security')];
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
                'constants' => ['SG_SECURITY_VERSION'],
                'classes'   => ['SG_Security\\Loader'],
                'enabled'   => function () {
                    return self::optionSays('sg_security_sg2fa');
                },
                'where'     => __('Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=login-settings'
            ],
            [
                'plugin'    => 'two-factor/two-factor.php',
                'name'      => __('Two Factor', 'fluent-security'),
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
                'classes'   => ['WordfenceLS\\Controller_TOTP'],
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
                'plugin'    => 'two-factor-authentication/two-factor-authentication.php',
                'name'      => __('Two Factor Authentication', 'fluent-security'),
                'classes'   => ['Simba_Two_Factor_Authentication'],
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
                'plugin'    => 'rublon/rublon.php',
                'name'      => __('Rublon Multi-Factor Authentication', 'fluent-security'),
                'constants' => ['RUBLON_VERSION'],
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
                 * No answer attempted. The obvious one - look for the login-security classes
                 * the standalone plugin uses - reads their absence as "the feature is off",
                 * and that is a guess about somebody else's load order dressed up as a fact.
                 * Guessing wrong there drops a real conflict silently, which is the one
                 * failure this check must not have. Its settings live in Wordfence's own
                 * tables either way, so a maybe is the honest answer.
                 */
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
                'classes'   => ['AIO_WP_Security'],
                'enabled'   => function () {
                    return self::optionSays('aiowps_enable_totp');
                },
                'where'     => __('WP Security → Two Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=aiowpsec',
                'certain'   => false
            ],
            [
                'plugin'    => 'wp-simple-firewall/icwp-wpsf.php',
                'name'      => __('Shield Security', 'fluent-security'),
                'constants' => ['ICWP_WPSF_VERSION'],
                'where'     => __('Shield → Login Protection → Multi-Factor Authentication', 'fluent-security'),
                'url'       => 'admin.php?page=icwp-wpsf-plugin',
                'certain'   => false
            ],
            [
                'plugin'    => 'defender-security/wp-defender.php',
                'name'      => __('Defender Security', 'fluent-security'),
                'constants' => ['DEFENDER_VERSION'],
                'classes'   => ['WP_Defender\\Controller\\Two_Factor'],
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
    protected static function pluginSays($class, $method, $args = [])
    {
        if (!method_exists($class, $method)) {
            return null;
        }

        return call_user_func_array([$class, $method], $args);
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
    protected static function optionSays($name)
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

    /**
     * @param array $rivals
     * @return array
     */
    protected static function describe($rivals)
    {
        return array_map(function ($rival) {
            if (empty($rival['where'])) {
                return (string)$rival['name'];
            }

            return sprintf(
                /* translators: 1: plugin name, 2: where its two factor setting lives */
                __('%1$s - its second factor is at %2$s', 'fluent-security'),
                $rival['name'],
                $rival['where']
            );
        }, $rivals);
    }

    /**
     * @param array $names
     * @return string
     */
    protected function confirmedTitle($names)
    {
        if (count($names) === 1) {
            return sprintf(
                /* translators: %s: plugin name */
                __('%s is also running two-factor authentication', 'fluent-security'),
                $names[0]
            );
        }

        return __('Other plugins are also running two-factor authentication', 'fluent-security');
    }

    /**
     * @param array $names
     * @return string
     */
    protected function possibleTitle($names)
    {
        if (count($names) === 1) {
            return sprintf(
                /* translators: %s: plugin name */
                __('%s may be running two-factor authentication as well', 'fluent-security'),
                $names[0]
            );
        }

        return __('Other plugins may be running two-factor authentication as well', 'fluent-security');
    }
}
