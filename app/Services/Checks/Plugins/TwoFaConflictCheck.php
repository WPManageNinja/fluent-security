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
     * The known plugins, and where each one keeps the switch.
     *
     * `certain` is the claim being made. True means we can see that a second factor is
     * running: either the plugin exists only to provide one, or we can read its own toggle
     * and it says yes. False means the plugin has a second factor among its features and the
     * setting is somewhere we cannot read - its own database table, a serialised blob - so
     * the honest thing is to name it and let the reader look.
     *
     * `option` is that toggle where there is one to read. Absent means the plugin is a
     * second factor and nothing else, so being active is the whole answer.
     *
     * @return array
     */
    public static function knownRivals()
    {
        $rivals = [
            [
                'plugin'  => 'sg-security/sg-security.php',
                'name'    => __('Security Optimizer by SiteGround', 'fluent-security'),
                'option'  => 'sg_security_sg2fa',
                'where'   => __('Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'     => 'admin.php?page=login-settings',
                'certain' => true
            ],
            [
                'plugin'  => 'two-factor/two-factor.php',
                'name'    => __('Two Factor', 'fluent-security'),
                'where'   => __('Users → Profile → Two-Factor Options', 'fluent-security'),
                'url'     => 'profile.php',
                'certain' => true
            ],
            [
                'plugin'  => 'wp-2fa/wp-2fa.php',
                'name'    => __('WP 2FA by Melapress', 'fluent-security'),
                'where'   => __('WP 2FA → Settings', 'fluent-security'),
                'url'     => 'admin.php?page=wp-2fa-policies',
                'certain' => true
            ],
            [
                'plugin'  => 'wordfence-login-security/wordfence-login-security.php',
                'name'    => __('Wordfence Login Security', 'fluent-security'),
                'where'   => __('Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'     => 'admin.php?page=WFLS',
                'certain' => true
            ],
            [
                'plugin'  => 'miniorange-2-factor-authentication/miniorange_2_factor_settings.php',
                'name'    => __('miniOrange 2-Factor Authentication', 'fluent-security'),
                'where'   => __('miniOrange 2-Factor → Two Factor', 'fluent-security'),
                'url'     => 'admin.php?page=miniOrange_2_factor_settings',
                'certain' => true
            ],
            [
                'plugin'  => 'two-factor-authentication/two-factor-authentication.php',
                'name'    => __('Two Factor Authentication', 'fluent-security'),
                'where'   => __('Users → Two Factor Authentication', 'fluent-security'),
                'url'     => 'profile.php',
                'certain' => true
            ],
            [
                'plugin'  => 'google-authenticator/google-authenticator.php',
                'name'    => __('Google Authenticator', 'fluent-security'),
                'where'   => __('Users → Profile → Google Authenticator Settings', 'fluent-security'),
                'url'     => 'profile.php',
                'certain' => true
            ],
            [
                'plugin'  => 'rublon/rublon.php',
                'name'    => __('Rublon Multi-Factor Authentication', 'fluent-security'),
                'where'   => __('Rublon → Settings', 'fluent-security'),
                'url'     => 'admin.php?page=rublon',
                'certain' => true
            ],
            /*
             * Below here the second factor is one feature among many and its setting is not
             * in an option we can read. Named rather than guessed at.
             */
            [
                'plugin'  => 'wordfence/wordfence.php',
                'name'    => __('Wordfence Security', 'fluent-security'),
                'where'   => __('Wordfence → Login Security → Two-Factor Authentication', 'fluent-security'),
                'url'     => 'admin.php?page=WFLS',
                'certain' => false
            ],
            [
                'plugin'  => 'better-wp-security/better-wp-security.php',
                'name'    => __('Solid Security (formerly iThemes Security)', 'fluent-security'),
                'where'   => __('Security → Settings → Two-Factor', 'fluent-security'),
                'url'     => 'admin.php?page=itsec',
                'certain' => false
            ],
            [
                'plugin'  => 'all-in-one-wp-security-and-firewall/wp-security.php',
                'name'    => __('All-In-One Security (AIOS)', 'fluent-security'),
                'where'   => __('WP Security → Two Factor Authentication', 'fluent-security'),
                'url'     => 'admin.php?page=aiowpsec',
                'certain' => false
            ],
            [
                'plugin'  => 'wp-simple-firewall/icwp-wpsf.php',
                'name'    => __('Shield Security', 'fluent-security'),
                'where'   => __('Shield → Login Protection → Multi-Factor Authentication', 'fluent-security'),
                'url'     => 'admin.php?page=icwp-wpsf-plugin',
                'certain' => false
            ],
            [
                'plugin'  => 'defender-security/wp-defender.php',
                'name'    => __('Defender Security', 'fluent-security'),
                'where'   => __('Defender → 2FA', 'fluent-security'),
                'url'     => 'admin.php?page=wdf-advanced-tools',
                'certain' => false
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
     * @return array the entries that are active, each with `certain` resolved
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
                'plugin'  => '',
                'name'    => '',
                'where'   => '',
                'url'     => '',
                'certain' => false
            ], $rival);

            if (!$rival['plugin'] || !$rival['name'] || !in_array($rival['plugin'], $active, true)) {
                continue;
            }

            /*
             * A toggle we can read decides both questions at once: off means there is no
             * conflict to report, on means the claim is certain rather than a maybe.
             */
            if (!empty($rival['option'])) {
                if (!get_option($rival['option'])) {
                    continue;
                }

                $rival['certain'] = true;
            }

            $found[] = $rival;
        }

        return $found;
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
