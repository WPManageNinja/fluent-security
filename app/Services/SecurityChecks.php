<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;
use FluentAuth\App\Services\TwoFa\WebAuthn\RelyingParty;

/**
 * The security checklist on the dashboard, and the one-click way to satisfy an item.
 *
 * A check is `done` or `todo`, and separately it is scored or not. Only the protections
 * this plugin recommends for every site count towards the score, so the score is reachable
 * - the rest are shown below it as things to weigh up. What "recommended" means comes from
 * Helper::getRecommendedSettings() rather than from anything written here, so the checklist
 * and the "apply recommended" button cannot disagree.
 *
 * The rule this list is built to obey: nothing on it may scold a site for a configuration
 * somebody chose on purpose. An early version marked sites down for not blocking
 * application passwords - a thing plenty of sites legitimately depend on - and a list that
 * does that teaches people to ignore the list. Which is why a recommendation that does not
 * suit every site either goes unscored, goes in as advice, or does not go on the list at
 * all.
 */
class SecurityChecks
{
    /**
     * The whole checklist, scored items first.
     *
     * @return array
     */
    public static function get()
    {
        $settings = Helper::getAuthSettings();

        $items = [];

        foreach (self::definitions() as $key => $definition) {
            $items[] = self::evaluate($key, $definition, $settings);
        }

        $scored = array_values(array_filter($items, function ($item) {
            return $item['scored'];
        }));

        $done = array_values(array_filter($scored, function ($item) {
            return $item['state'] === 'done';
        }));

        return [
            'items' => $items,
            'done'  => count($done),
            'total' => count($scored)
        ];
    }

    /**
     * One check, evaluated against the current settings.
     *
     * For callers that need a single item's title, reasoning and state without walking the
     * whole list - the setup wizard shows the checklist's own words under the toggle that
     * satisfies a check, so that a site is never given one explanation there and a
     * different one here.
     *
     * @param string $key
     * @return array|null
     */
    public static function find($key)
    {
        $definitions = self::definitions();

        if (!isset($definitions[$key])) {
            return null;
        }

        return self::evaluate($key, $definitions[$key], Helper::getAuthSettings());
    }

    /**
     * Turns on the protection a single check asks for.
     *
     * Takes the name of a check, not a setting and a value: the caller says which
     * recommendation to apply and this decides what that means, so the endpoint can never
     * be talked into writing an arbitrary setting. Every reason to refuse is checked again
     * here rather than trusted to the button being hidden.
     *
     * @param string $key
     * @return array|\WP_Error
     */
    public static function apply($key)
    {
        $definitions = self::definitions();

        if (!isset($definitions[$key])) {
            return new \WP_Error(
                'unknown_check',
                __('That is not something this plugin can turn on.', 'fluent-security'),
                ['status' => 404]
            );
        }

        $settings = Helper::getAuthSettings();
        $item = self::evaluate($key, $definitions[$key], $settings);

        if ($item['state'] === 'done') {
            return new \WP_Error(
                'already_done',
                __('This is already turned on.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if ($item['action'] !== 'enable') {
            return new \WP_Error(
                'not_applicable',
                __('This one has to be set up before it can be switched on.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $recommended = Helper::getRecommendedSettings();

        foreach ($definitions[$key]['settings'] as $settingKey) {
            $settings[$settingKey] = Arr::get($recommended, $settingKey, 'yes');
        }

        /*
         * The whole option is written back, not the keys that changed. Saving replaces it
         * wholesale, so posting a slice erases every setting the slice does not mention.
         */
        update_option('__fls_auth_settings', $settings, false);

        Helper::resetStatics();

        return [
            'settings' => Helper::getAuthSettings(),
            'checklist' => self::get(),
            'message'  => sprintf(
                /* translators: %s: the name of the security check that was turned on */
                __('%s is now on.', 'fluent-security'),
                $definitions[$key]['title']
            )
        ];
    }

    /**
     * @param string $key
     * @param array $definition
     * @param array $settings
     * @return array
     */
    private static function evaluate($key, $definition, $settings)
    {
        $done = call_user_func($definition['done'], $settings);

        $item = [
            'key'     => $key,
            'title'   => $definition['title'],
            /*
             * One line on why it matters, for the finding row on the security screen. The
             * checklist on the dashboard never had room for it and did without; a reader who
             * has to decide whether to press the button needs it.
             */
            'why'     => Arr::get($definition, 'why', ''),
            'group'   => Arr::get($definition, 'group', 'login'),
            'scored'  => $definition['scored'],
            /*
             * Sound practice rather than a protection every site should have on. Carried
             * separately from `scored` because they answer different questions: an unscored
             * check is one the score cannot reach, advice is one nothing is wrong about.
             */
            'advice'  => !empty($definition['advice']),
            'state'   => $done ? 'done' : 'todo',
            'action'  => $definition['settings'] ? 'enable' : 'navigate',
            'route'   => $definition['route'],
            'section' => Arr::get($definition, 'section', '')
        ];

        return $item;
    }

    /**
     * @return array
     */
    private static function definitions()
    {
        return [
            'two_fa'             => [
                'title'    => __('Two-factor authentication', 'fluent-security'),
                'why'      => __('Lets people add a code from an app or their email to their sign-in. A stolen password alone is then not enough to get in.', 'fluent-security'),
                'group'    => 'login',
                'scored'   => true,
                'route'    => 'settings_general',
                'section'  => 'two_fa',
                'settings' => ['totp_2fa', 'email2fa', 'email2fa_roles', 'totp_2fa_roles', 'passkey_2fa'],
                /*
                 * Any factor counts. Turning them on only lets people set one up - the
                 * roles that must have one are left alone on purpose, because imposing
                 * that from a one-click button is how an administrator locks themselves out.
                 *
                 * Passkeys count, and their absence here was a straightforward bug: a site
                 * running passkeys and nothing else was told it had no second factor and
                 * docked the points for it, while the plugin's own enforcement was happily
                 * accepting one as meeting a requirement. The strongest method the plugin
                 * offers is not the one to leave out of the tally.
                 *
                 * The switch is not enough on its own, though, which is why this asks
                 * RelyingParty::isSupported() as well: over plain http no passkey can be
                 * created whatever the setting says, and ticking this off for one would
                 * score a site as having a second factor that nobody on it can register.
                 * That is the same question PasskeyTwoFaMethod::isSwitchedOn() asks, and
                 * the passkey card on the settings screen says so in as many words.
                 */
                'done'     => function ($settings) {
                    $passkeyOn = Arr::get($settings, 'passkey_2fa') === 'yes'
                        && RelyingParty::isSupported();

                    return $passkeyOn
                        || Arr::get($settings, 'totp_2fa') === 'yes'
                        || Arr::get($settings, 'email2fa') === 'yes';
                }
            ],
            /*
             * Advice, and unscored with it. Login alerts are worth having on the accounts that
             * can do damage, and worth not having on the ones that sign in all day - a mailbox
             * that fills up with sign-ins nobody reads is worse than no alerts at all, because
             * the one that mattered arrives in a folder somebody set up a filter for.
             *
             * Which is a judgement about how a particular site is staffed, not a protection
             * every site should have on. So it is offered rather than counted, and the roles
             * this recommends are the high-privilege ones only - see
             * Helper::getRecommendedSettings().
             */
            'notifications'      => [
                'title'    => __('Get an email when an administrator signs in', 'fluent-security'),
                'why'      => __('If someone else signs in to an administrator account, you find out the same day. Keep it to roles that sign in rarely, so the emails stay worth reading.', 'fluent-security'),
                'group'    => 'login',
                'scored'   => false,
                'advice'   => true,
                'route'    => 'settings_general',
                'section'  => 'notifications',
                'settings' => ['notification_user_roles', 'notification_email'],
                'done'     => function ($settings) {
                    return !empty(Arr::get($settings, 'notification_user_roles'))
                        && !empty(Arr::get($settings, 'notification_email'));
                }
            ],
            'disable_xmlrpc'     => [
                'title'    => __('Block the old remote sign-in route (XML-RPC)', 'fluent-security'),
                'why'      => __('Few sites still use it, and it is a favourite way to try thousands of passwords at once. Skip this if you rely on the WordPress mobile app or Jetpack.', 'fluent-security'),
                'group'    => 'config',
                'scored'   => true,
                'route'    => 'settings_general',
                'section'  => 'core',
                'settings' => ['disable_xmlrpc'],
                'done'     => function ($settings) {
                    return Arr::get($settings, 'disable_xmlrpc') === 'yes';
                }
            ],
            'disable_users_rest' => [
                'title'    => __('Hide usernames from the public', 'fluent-security'),
                'why'      => __('Right now anyone can look up the usernames on your site. A username is half of every login.', 'fluent-security'),
                'group'    => 'config',
                'scored'   => true,
                'route'    => 'settings_general',
                'section'  => 'core',
                'settings' => ['disable_users_rest'],
                'done'     => function ($settings) {
                    return Arr::get($settings, 'disable_users_rest') === 'yes';
                }
            ],
            'secure_signup_form' => [
                'title'    => __('Verify email addresses on signup', 'fluent-security'),
                'why'      => __('Without it, anyone can register accounts in bulk with addresses they do not own.', 'fluent-security'),
                'group'    => 'login',
                'scored'   => true,
                'route'    => 'settings_general',
                'section'  => 'core',
                'settings' => ['secure_signup_form'],
                'done'     => function ($settings) {
                    return Arr::get($settings, 'secure_signup_form') === 'yes';
                }
            ],

            'integrity_scan'     => [
                /*
                 * No settings to write: file monitoring is a service that has to be set up
                 * before it can be switched on, so this one can only point at where to do
                 * that. It is out of the score for the same reason - most sites would sit
                 * at four out of five forever through no fault of their configuration.
                 */
                'title'    => __('Watch your WordPress files for changes', 'fluent-security'),
                'why'      => __('This is the only check that can tell you a file was edited after somebody got in.', 'fluent-security'),
                'group'    => 'files',
                'scored'   => false,
                'route'    => 'security_scans',
                'settings' => [],
                'done'     => function () {
                    $scan = IntegrityHelper::getSettings();

                    return in_array(Arr::get($scan, 'status'), ['active', 'self'], true)
                        && Arr::get($scan, 'auto_scan') === 'yes';
                }
            ]
        ];
    }
}
