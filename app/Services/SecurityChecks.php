<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * The security checklist on the dashboard, and the one-click way to satisfy an item.
 *
 * A check is not a yes-or-no. The first version of this list was, and it marked a site
 * down for not blocking application passwords - a setting the plugin recommends leaving
 * alone, because blocking it breaks every integration on a site that uses it. A list that
 * scolds you for a deliberate configuration teaches you to ignore the list.
 *
 * So a check has a state:
 *
 * - `done`    the protection is on.
 * - `todo`    it is off, and turning it on is what this plugin recommends.
 * - `in_use`  it is off, and something on this site is relying on that. Reported as a fact
 *             with the evidence for it, never as a failing, and never one-click fixable.
 *
 * And a check is either scored or not. Only the ones this plugin recommends for every site
 * count towards the score, so the score is reachable - the rest are shown below it as
 * things to weigh up. What "recommended" means comes from Helper::getRecommendedSettings()
 * rather than from anything written here, so the checklist and the "apply recommended"
 * button cannot disagree.
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

        /*
         * Ordered before the "can this be turned on from here" check, and not folded into
         * it, because a check in use reports itself as navigate-only - so testing that first
         * would refuse for the right reason while giving the wrong one, and the reason is
         * the entire value of this guard: it is what tells the caller what would break.
         *
         * The evidence is re-read here rather than taken from the request. Between the
         * dashboard loading and this being clicked somebody may have created an application
         * password, and the point of the check is not to cut off what they just set up.
         */
        if ($item['state'] === 'in_use') {
            return new \WP_Error(
                'in_use',
                $item['note'] ?: __('Something on this site is relying on this.', 'fluent-security'),
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
            'state'   => $done ? 'done' : 'todo',
            'action'  => $definition['settings'] ? 'enable' : 'navigate',
            'note'    => '',
            'route'   => $definition['route'],
            'section' => Arr::get($definition, 'section', '')
        ];

        if (isset($definition['evidence'])) {
            $item = call_user_func($definition['evidence'], $item);
        }

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
                'why'      => __('A stolen password is not enough to get in when a second step is asked for.', 'fluent-security'),
                'group'    => 'login',
                'scored'   => true,
                'route'    => 'settings_general',
                'section'  => 'two_fa',
                'settings' => ['totp_2fa', 'email2fa', 'email2fa_roles', 'totp_2fa_roles'],
                /*
                 * Either factor counts. Turning them on only lets people set one up - the
                 * roles that must have one are left alone on purpose, because imposing
                 * that from a one-click button is how an administrator locks themselves out.
                 */
                'done'     => function ($settings) {
                    return Arr::get($settings, 'totp_2fa') === 'yes'
                        || Arr::get($settings, 'email2fa') === 'yes';
                }
            ],
            'notifications'      => [
                'title'    => __('Alert admins about logins', 'fluent-security'),
                'why'      => __('An email when someone signs in is how a stolen account gets noticed on the day, not the week after.', 'fluent-security'),
                'group'    => 'login',
                'scored'   => true,
                'route'    => 'settings_general',
                'section'  => 'notifications',
                'settings' => ['notification_user_roles', 'notification_email'],
                'done'     => function ($settings) {
                    return !empty(Arr::get($settings, 'notification_user_roles'))
                        && !empty(Arr::get($settings, 'notification_email'));
                }
            ],
            'disable_xmlrpc'     => [
                'title'    => __('Block XML-RPC requests', 'fluent-security'),
                'why'      => __('An old way in that few sites still use, and a favourite route for guessing passwords in bulk.', 'fluent-security'),
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
                'title'    => __('Hide the public user list', 'fluent-security'),
                'why'      => __('By default anyone can read the usernames on your site, which is half of every login.', 'fluent-security'),
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

            /*
             * Not scored, because there is no answer that is right for every site - see
             * Helper::getRecommendedSettings(). What makes it worth showing anyway is that
             * the answer for *this* site can be looked up rather than guessed at.
             */
            'disable_app_login'  => [
                'title'    => __('Block application passwords', 'fluent-security'),
                'why'      => __('These sign in without a second step, so any that exist bypass two-factor entirely.', 'fluent-security'),
                'group'    => 'login',
                'scored'   => false,
                'route'    => 'settings_general',
                'section'  => 'core',
                'settings' => ['disable_app_login'],
                'done'     => function ($settings) {
                    return Arr::get($settings, 'disable_app_login') === 'yes';
                },
                'evidence' => function ($item) {
                    return self::appPasswordEvidence($item);
                }
            ],
            'integrity_scan'     => [
                /*
                 * No settings to write: file monitoring is a service that has to be set up
                 * before it can be switched on, so this one can only point at where to do
                 * that. It is out of the score for the same reason - most sites would sit
                 * at four out of five forever through no fault of their configuration.
                 */
                'title'    => __('Watch core files for changes', 'fluent-security'),
                'why'      => __('Nothing else on this list can tell you that a file was edited after somebody got in.', 'fluent-security'),
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

    /**
     * Whether anything on this site signs in with an application password.
     *
     * Read from the passwords themselves rather than from the auth log: a successful REST
     * login does not go through the login form and leaves no entry, so the log can only
     * ever prove that nothing has failed. A password that exists is a thing somebody
     * created for something, which is the fact worth knowing before blocking the lot.
     *
     * @param array $item
     * @return array
     */
    private static function appPasswordEvidence($item)
    {
        if ($item['state'] === 'done') {
            $item['note'] = __('Blocked. Nothing can sign in over the REST API with one.', 'fluent-security');

            return $item;
        }

        $users = self::usersWithAppPasswords();

        if ($users) {
            $item['state'] = 'in_use';
            $item['action'] = 'navigate';
            $item['route'] = 'settings_two_fa_enrollment';
            $item['note'] = sprintf(
                /* translators: %s: number of users */
                _n(
                    'In use: %s user has an application password. Blocking these would cut off whatever it was made for.',
                    'In use: %s users have application passwords. Blocking these would cut off whatever they were made for.',
                    $users,
                    'fluent-security'
                ),
                number_format_i18n($users)
            );

            return $item;
        }

        $item['note'] = __('Nobody has one, so blocking them costs this site nothing.', 'fluent-security');

        return $item;
    }

    /**
     * @return int
     */
    private static function usersWithAppPasswords()
    {
        if (!class_exists('\WP_Application_Passwords')) {
            return 0;
        }

        $query = new \WP_User_Query([
            'number'     => 1,
            'fields'     => 'ID',
            'meta_query' => [
                [
                    'key'     => \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS,
                    'compare' => 'EXISTS'
                ]
            ]
        ]);

        return (int)$query->get_total();
    }
}
