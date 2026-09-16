<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

/**
 * The first run: what it asks, and what an answer means.
 *
 * A new install has every protection off and a checklist explaining what is wrong, which
 * is a to-do list handed to somebody who has not been told what the words mean yet. This
 * walks them through it instead, one question per screen, and writes the result once.
 *
 * Three rules hold this together, and all three are inherited rather than invented:
 *
 * - Every value it offers comes from Helper::getRecommendedSettings(). Nothing here
 *   hardcodes what "recommended" means, so the wizard and the security checklist cannot
 *   end up recommending different things.
 *
 * - An answer names a step, not a setting. Like SecurityChecks::apply(), the endpoint
 *   decides what a step means rather than being handed settings to write, so it cannot be
 *   talked into writing something no screen offered.
 *
 * - Nothing is written until the last screen. Saving replaces the whole settings option
 *   (see SecurityChecks::apply), so a write per screen would be five chances to leave a
 *   site half configured behind a closed browser.
 *
 * And it keeps no state of its own. Whether the wizard is owed is read from the settings
 * option rather than recorded beside it - see isRequired().
 *
 * Why the steps are declared here rather than as flags on SecurityChecks::definitions():
 * one screen can cover several checks - the hardening screen covers three - and a headline
 * and a preview are presentation, which is not what that list is for. What the two share is
 * the only thing they must agree on, which is whether a protection is on and what it should
 * be. Check-backed steps name their check and read its title and reasoning from there.
 */
class Onboarding
{
    /**
     * Whether this site still has a first run waiting for it.
     *
     * There is no flag, because there is nothing a flag would know that this does not.
     * The settings option is written the first time anything is saved - by the wizard, by
     * the settings screen, by the checklist - so a site that has one has been configured,
     * and a site that has not is a site nobody has set up yet. That is the whole question
     * the wizard exists to ask.
     *
     * Asked rather than recorded, so an install that arrives by any route - a fresh
     * install, the updater, a manual reactivation, a file copy, a restored backup - is
     * read the same way, with no migration to carry a flag to sites that predate it.
     *
     * @return bool
     */
    public static function isRequired()
    {
        return !get_option('__fls_auth_settings');
    }

    /**
     * Everything the wizard needs to draw itself, in one request.
     *
     * @return array
     */
    public static function payload()
    {
        $settings = Helper::getAuthSettings();
        $recommended = Helper::getRecommendedSettings();

        return [
            'steps'       => self::steps($settings, $recommended),
            'settings'    => $settings,
            'recommended' => $recommended,
            'user_roles'  => Helper::getUserRoles(),
            'admin_email' => get_option('admin_email'),
            'site_name'   => get_bloginfo('name'),
            /*
             * The connection step is drawn from this, and it is read from the
             * administrator's own request - so it describes the connection of the person
             * who is about to answer the question, which is the whole point of asking.
             */
            'connection'  => ProxyDetection::detect()
        ];
    }

    /**
     * The screens, in order, with the current state of what each one asks about.
     *
     * @param array $settings
     * @param array $recommended
     * @return array
     */
    public static function steps($settings = null, $recommended = null)
    {
        $settings = $settings === null ? Helper::getAuthSettings() : $settings;
        $recommended = $recommended === null ? Helper::getRecommendedSettings() : $recommended;

        $steps = [];

        foreach (self::definitions() as $id => $definition) {
            if (isset($definition['available']) && !call_user_func($definition['available'])) {
                continue;
            }

            $step = [
                'id'        => $id,
                'title'     => $definition['title'],
                'headline'  => $definition['headline'],
                'why'       => $definition['why'],
                'preview'   => $definition['preview'],
                'skippable' => !isset($definition['skippable']) || call_user_func($definition['skippable']),
                'checks'    => []
            ];

            /*
             * The reasoning shown under a check-backed toggle is the checklist's own, so a
             * site is never given one explanation here and a different one on the screen
             * that later tells it the same thing is still outstanding.
             */
            foreach (Arr::get($definition, 'checks', []) as $key) {
                $check = SecurityChecks::find($key);

                if ($check) {
                    $step['checks'][] = $check;
                }
            }

            $step['answer'] = call_user_func($definition['answer'], $settings, $recommended);

            $steps[] = $step;
        }

        return $steps;
    }

    /**
     * The screens themselves.
     *
     * `answer` produces what the screen should open with: the recommended value, except
     * where the site has already been configured, in which case what it already has -
     * somebody who changed a setting before walking the wizard should not be shown a
     * screen proposing to undo it.
     *
     * @return array
     */
    private static function definitions()
    {
        return apply_filters('fluent_auth/onboarding_steps', [

            /*
             * First, because it can invalidate every screen after it. Behind an undeclared
             * proxy every visitor resolves to the same address, which makes the attempt
             * limit count the whole internet as one person - so a site in that state is
             * being asked to tune a limit that cannot work yet.
             */
            'connection' => [
                'title'     => __('Connection', 'fluent-security'),
                'headline'  => __('Is this the address you are visiting from?', 'fluent-security'),
                'why'       => __('Failed logins are counted per visitor address, so the site has to be seeing the real one.', 'fluent-security'),
                'preview'   => 'connection',
                'checks'    => [],
                /*
                 * Asked only where the answer can still change something.
                 *
                 * Cloudflare proves itself against published ranges, so the resolver
                 * already handles it and there is nothing to ask.
                 *
                 * Nor is it asked where nothing is relaying at all - the request arrived
                 * from a public address carrying no forwarding headers, which is nearly
                 * every WordPress site. The reader would be opening their setup on a
                 * question about reverse proxies, a thing their site does not have, and
                 * the only available answer is the one already true. The settings screen
                 * still carries the way in for somebody who knows better than the
                 * detection does.
                 *
                 * A site with a proxy already declared is skipped for a subtler reason.
                 * "Is this your address?" reads yes in two different situations - no proxy
                 * at all, and a proxy that is declared and working - because in both the
                 * resolver has arrived at the reader's real address. Asking anyway would
                 * mean reading a yes from a correctly configured site as "there is no
                 * proxy", and the only thing to do with that would be to undo a working
                 * configuration. So the question is not put where it cannot be answered
                 * unambiguously; the settings screen is where a declared proxy is changed.
                 */
                'available' => function () {
                    $detection = ProxyDetection::detect();

                    if ($detection['status'] === ProxyDetection::STATUS_CLOUDFLARE) {
                        return false;
                    }

                    if ($detection['status'] === ProxyDetection::STATUS_NONE) {
                        return false;
                    }

                    return !Helper::getTrustedProxies() || ProxyDetection::isAmbiguous();
                },
                /*
                 * The one screen that cannot be waved past, and only in the state where
                 * waving past it breaks the rest. See ProxyDetection::isAmbiguous().
                 */
                'skippable' => function () {
                    return !ProxyDetection::isAmbiguous();
                },
                /*
                 * Neither choice is preselected. There is no recommended answer to a
                 * question about somebody else's server - which is also why none of this
                 * appears in Helper::getRecommendedSettings() - and a preselected one here
                 * would be a guess the reader could pass without noticing.
                 */
                'answer'    => function ($settings) {
                    $detection = ProxyDetection::detect();

                    return [
                        'mode'            => '',
                        'trusted_proxies' => Arr::get($settings, 'trusted_proxies')
                            ?: Arr::get($detection, 'suggested_proxy', ''),
                        'proxy_ip_header' => Arr::get($settings, 'proxy_ip_header')
                            ?: Arr::get($detection, 'suggested_header', '')
                    ];
                }
            ],

            'two_fa'      => [
                'title'    => __('Two-factor', 'fluent-security'),
                'headline' => __('Add a second step when people sign in?', 'fluent-security'),
                'why'      => __('With a second step, a stolen password on its own is not enough to get in.', 'fluent-security'),
                'preview'  => 'two_factor',
                'checks'   => ['two_fa'],
                'answer'   => function ($settings, $recommended) {
                    $configured = Arr::get($settings, 'totp_2fa') === 'yes'
                        || Arr::get($settings, 'email2fa') === 'yes';

                    if ($configured) {
                        return [
                            'totp'  => Arr::get($settings, 'totp_2fa') === 'yes',
                            'email' => Arr::get($settings, 'email2fa') === 'yes',
                            'roles' => array_values(array_unique(array_merge(
                                (array)Arr::get($settings, 'totp_2fa_roles', []),
                                (array)Arr::get($settings, 'email2fa_roles', [])
                            )))
                        ];
                    }

                    /*
                     * Which comes out as emailed codes on and the authenticator app off -
                     * see Helper::getRecommendedSettings() for why that pair is the one a
                     * site nobody has looked at should open on.
                     *
                     * The roles follow the method that is actually on, so the list the
                     * reader sees is the list of people who will start getting a code.
                     */
                    return [
                        'totp'  => Arr::get($recommended, 'totp_2fa') === 'yes',
                        'email' => Arr::get($recommended, 'email2fa') === 'yes',
                        'roles' => (array)Arr::get(
                            $recommended,
                            Arr::get($recommended, 'email2fa') === 'yes' ? 'email2fa_roles' : 'totp_2fa_roles',
                            []
                        )
                    ];
                }
            ],

            /*
             * Not a checklist item, deliberately. The limit ships at the recommended value
             * and the settings screen refuses to save it empty, so a check for it would
             * read `done` on every site that has ever existed and teach people that the
             * list is padding. It is here because the number is worth seeing once, beside
             * what it does to somebody who gets their own password wrong.
             */
            'login_limit' => [
                'title'    => __('Failed attempts', 'fluent-security'),
                'headline' => __('How many failed attempts before a visitor is blocked?', 'fluent-security'),
                'why'      => __('A low number stops password guessing, but set it too low and people who mistype their own password get locked out.', 'fluent-security'),
                'preview'  => 'lockout',
                'checks'   => [],
                'answer'   => function ($settings, $recommended) {
                    return [
                        'limit'  => (int)(Arr::get($settings, 'login_try_limit')
                            ?: Arr::get($recommended, 'login_try_limit')),
                        'timing' => (int)(Arr::get($settings, 'login_try_timing')
                            ?: Arr::get($recommended, 'login_try_timing'))
                    ];
                }
            ],

            'hardening'   => [
                'title'    => __('Protections', 'fluent-security'),
                'headline' => __('Turn these protections on?', 'fluent-security'),
                'why'      => __('Each one closes something WordPress leaves open by default that most sites never use.', 'fluent-security'),
                'preview'  => 'signup',
                'checks'   => ['disable_xmlrpc', 'disable_users_rest', 'secure_signup_form'],
                'answer'   => function ($settings, $recommended) {
                    $answer = [];

                    foreach (['disable_xmlrpc', 'disable_users_rest', 'secure_signup_form'] as $key) {
                        /*
                         * Already on stays on; otherwise offer what is recommended. Nothing
                         * here proposes turning a protection off.
                         */
                        $answer[$key] = Arr::get($settings, $key) === 'yes'
                            || Arr::get($recommended, $key) === 'yes';
                    }

                    return $answer;
                }
            ],

            'alerts'      => [
                'title'    => __('Alerts', 'fluent-security'),
                'headline' => __('Want an email when important accounts sign in?', 'fluent-security'),
                'why'      => __('A sign-in you did not make is the first sign of a stolen account, and an email is how you find out the same day.', 'fluent-security'),
                'preview'  => 'email',
                'checks'   => ['notifications'],
                'answer'   => function ($settings, $recommended) {
                    $roles = (array)Arr::get($settings, 'notification_user_roles', []);

                    return [
                        'enabled' => true,
                        'roles'   => $roles ?: (array)Arr::get($recommended, 'notification_user_roles', []),
                        'email'   => Arr::get($settings, 'notification_email')
                            ?: Arr::get($recommended, 'notification_email', '{admin_email}')
                    ];
                }
            ]
        ]);
    }

    /**
     * Applies every answer, in one write, and closes the wizard.
     *
     * @param array $answers Keyed by step id.
     * @return array|\WP_Error
     */
    public static function complete($answers)
    {
        if (!self::isRequired()) {
            return new \WP_Error(
                'already_onboarded',
                __('Setup has already been completed on this site.', 'fluent-security'),
                ['status' => 422]
            );
        }

        return self::write(is_array($answers) ? $answers : []);
    }

    /**
     * @param array $answers
     * @return array|\WP_Error
     */
    private static function write($answers)
    {
        $settings = Helper::getAuthSettings();
        $recommended = Helper::getRecommendedSettings();
        $applied = [];

        foreach (self::definitions() as $id => $definition) {
            if (!array_key_exists($id, $answers)) {
                continue;
            }

            if (isset($definition['available']) && !call_user_func($definition['available'])) {
                continue;
            }

            $result = self::applyStep($id, $answers[$id], $settings, $recommended);

            if (is_wp_error($result)) {
                return $result;
            }

            $settings = $result['settings'];

            foreach ($result['applied'] as $line) {
                $applied[] = $line;
            }
        }

        /*
         * One write. Saving replaces the option wholesale, so this is the only place the
         * wizard touches it - see the note on SecurityChecks::apply().
         */
        update_option('__fls_auth_settings', $settings, false);

        Helper::resetStatics();

        return [
            'settings'  => Helper::getAuthSettings(),
            'checklist' => SecurityChecks::get(),
            'applied'   => $applied
        ];
    }

    /**
     * Turns one step's answer into settings.
     *
     * Every branch decides for itself what the answer is allowed to mean. An answer is a
     * choice between the options a screen offered, never a value to be written through.
     *
     * Every switch on every screen is read with Arr::isTrue() rather than with empty().
     * The wizard sends its answers through jQuery.ajax, which form-encodes them, and
     * form encoding has no booleans: a switch the administrator turned off arrives here
     * as the string "false", which empty() reads as on. That made every switch in the
     * wizard one-way - it could turn a protection on, and silently refused to turn one
     * off - and reported the refusal back as "Turned on ..." on the summary screen.
     *
     * @param string $id
     * @param mixed $answer
     * @param array $settings
     * @param array $recommended
     * @return array|\WP_Error
     */
    private static function applyStep($id, $answer, $settings, $recommended)
    {
        $applied = [];

        if (!is_array($answer)) {
            $answer = [];
        }

        switch ($id) {

            case 'connection':
                $mode = Arr::get($answer, 'mode');

                if ($mode === 'proxy') {
                    $proxies = self::sanitizeProxyList(Arr::get($answer, 'trusted_proxies', ''));

                    if (!$proxies) {
                        return new \WP_Error(
                            'proxy_required',
                            __('Add the address of the proxy in front of this site.', 'fluent-security'),
                            ['status' => 422]
                        );
                    }

                    $settings['trusted_proxies'] = $proxies;
                    $settings['proxy_ip_header'] = self::sanitizeHeader(Arr::get($answer, 'proxy_ip_header', ''));

                    $applied[] = __('Saved the address of the proxy in front of this site.', 'fluent-security');
                }

                /*
                 * "That is me" is an answer, not an omission - it says the address the
                 * plugin resolved is the right one. There is nothing to write for it, and
                 * writing nothing is the correct outcome rather than a missed branch.
                 */
                break;

            case 'two_fa':
                $roles = self::sanitizeRoles(Arr::get($answer, 'roles', []));
                $totp = Arr::isTrue($answer, 'totp');
                $email = Arr::isTrue($answer, 'email');

                if (($totp || $email) && !$roles) {
                    return new \WP_Error(
                        'roles_required',
                        __('Choose at least one role to get the second step.', 'fluent-security'),
                        ['status' => 422]
                    );
                }

                $settings['totp_2fa'] = $totp ? 'yes' : 'no';
                $settings['email2fa'] = $email ? 'yes' : 'no';

                if ($totp) {
                    $settings['totp_2fa_roles'] = $roles;
                    $applied[] = __('Turned on authenticator apps.', 'fluent-security');
                }

                if ($email) {
                    $settings['email2fa_roles'] = $roles;
                    $applied[] = __('Turned on emailed sign-in codes.', 'fluent-security');
                }

                /*
                 * `totp_required_roles` is not written here, and not by accident. Offering a
                 * second step is safe on any site; requiring one from a wizard is how an
                 * administrator locks themselves out of the site they just installed this on.
                 */
                break;

            case 'login_limit':
                $limit = (int)Arr::get($answer, 'limit', 0);
                $timing = (int)Arr::get($answer, 'timing', 0);

                if ($limit < 1 || $limit > 100 || $timing < 1 || $timing > 1440) {
                    return new \WP_Error(
                        'invalid_limit',
                        __('Use between 1 and 100 attempts, and a window of up to 1440 minutes (one day).', 'fluent-security'),
                        ['status' => 422]
                    );
                }

                $settings['login_try_limit'] = $limit;
                $settings['login_try_timing'] = $timing;

                $applied[] = sprintf(
                    /* translators: 1: number of attempts, 2: number of minutes */
                    __('Set the limit to %1$d failed attempts in %2$d minutes.', 'fluent-security'),
                    $limit,
                    $timing
                );
                break;

            case 'hardening':
                $labels = [
                    'disable_xmlrpc'     => __('Blocked XML-RPC (an old remote publishing feature).', 'fluent-security'),
                    'disable_users_rest' => __('Hid usernames from the public.', 'fluent-security'),
                    'secure_signup_form' => __('Turned on email verification for new accounts.', 'fluent-security')
                ];

                foreach ($labels as $key => $label) {
                    $wanted = Arr::isTrue($answer, $key);

                    if ($wanted && Arr::get($settings, $key) !== 'yes') {
                        $applied[] = $label;
                    }

                    $settings[$key] = $wanted ? 'yes' : 'no';
                }
                break;

            case 'alerts':
                if (!Arr::isTrue($answer, 'enabled')) {
                    $settings['notification_user_roles'] = [];
                    break;
                }

                $roles = self::sanitizeRoles(Arr::get($answer, 'roles', []));
                $email = trim((string)Arr::get($answer, 'email', ''));

                if (!$roles) {
                    return new \WP_Error(
                        'roles_required',
                        __('Choose at least one role to be alerted about, or turn alerts off.', 'fluent-security'),
                        ['status' => 422]
                    );
                }

                /*
                 * `{admin_email}` is the shipped default and resolves at send time, so it
                 * is allowed through as itself rather than failing an email check.
                 */
                if ($email !== '{admin_email}' && !is_email($email)) {
                    return new \WP_Error(
                        'invalid_email',
                        __('That does not look like an email address.', 'fluent-security'),
                        ['status' => 422]
                    );
                }

                $settings['notification_user_roles'] = $roles;
                $settings['notification_email'] = $email ?: Arr::get($recommended, 'notification_email', '{admin_email}');

                $applied[] = __('Turned on sign-in alerts.', 'fluent-security');
                break;
        }

        return ['settings' => $settings, 'applied' => $applied];
    }

    /**
     * Leaves the wizard without turning anything on.
     *
     * It still writes, because being configured is what closes the wizard and there is no
     * flag to say so instead. What it writes changes nothing: these are the same defaults
     * getAuthSettings() already returns for a site with no option, so the site behaves
     * exactly as it did a moment earlier - it has simply answered, and the answer was no.
     *
     * @return array
     */
    public static function skip()
    {
        update_option('__fls_auth_settings', Helper::getAuthSettings(), false);

        Helper::resetStatics();

        return ['settings' => Helper::getAuthSettings()];
    }

    /**
     * Keeps only roles this site actually has.
     *
     * @param mixed $roles
     * @return array
     */
    private static function sanitizeRoles($roles)
    {
        if (!is_array($roles)) {
            return [];
        }

        $valid = array_keys(Helper::getUserRoles(true));

        $roles = array_map('sanitize_text_field', array_filter($roles, 'is_string'));

        return array_values(array_intersect($roles, $valid));
    }

    /**
     * @param mixed $value
     * @return string A comma separated list of addresses or CIDR ranges.
     */
    private static function sanitizeProxyList($value)
    {
        if (!is_string($value)) {
            return '';
        }

        $parts = array_filter(array_map('trim', explode(',', $value)));

        $parts = array_filter($parts, function ($part) {
            list($address) = array_pad(explode('/', $part, 2), 2, null);

            return (bool)filter_var($address, FILTER_VALIDATE_IP);
        });

        return implode(',', array_map('sanitize_text_field', $parts));
    }

    /**
     * @param mixed $value
     * @return string
     */
    private static function sanitizeHeader($value)
    {
        if (!is_string($value)) {
            return '';
        }

        return sanitize_text_field(trim($value));
    }
}
