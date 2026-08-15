<?php

namespace FluentAuth\App\Helpers;

class Helper
{
    private static $loginMedia = 'web';
    private static $authSettings = null;
    private static $socialAuthSettings = null;
    private static $resolvedIp = null;
    private static $trustedProxies = null;
    private static $tokenVerifiedLogin = false;
    private static $satisfiedFactors = null;

    public static function resetStatics()
    {
        self::$authSettings = null;
        self::$socialAuthSettings = null;
        self::$loginMedia = 'web';
        self::$resolvedIp = null;
        self::$trustedProxies = null;
        self::$tokenVerifiedLogin = false;
        self::$satisfiedFactors = null;
        \FluentAuth\App\Services\TwoFa\TwoFaService::resetMethods();
    }

    /**
     * Records everything the first step of the login in progress actually proved.
     *
     * The second factor is chosen against this set: a method proving something already
     * in it is skipped, one proving anything else is still required. It is a set rather
     * than a single value because one step can prove more than one thing - a social
     * login proves both the provider and, since the account is matched on a provider
     * verified address, the mailbox behind it.
     *
     * @param $factors array of AuthFactor constants
     * @return void
     */
    public static function setSatisfiedFactors($factors)
    {
        self::$satisfiedFactors = array_values(array_unique((array)$factors));
    }

    /**
     * Defaults to a password, because that is the only route reaching wp_authenticate
     * without having announced itself.
     *
     * @return array
     */
    public static function getSatisfiedFactors()
    {
        if (self::$satisfiedFactors === null) {
            return [\FluentAuth\App\Services\TwoFa\AuthFactor::KNOWLEDGE];
        }

        return self::$satisfiedFactors;
    }

    /**
     * Marks the login in progress as one where the user redeemed a token we emailed
     * them - a magic link or a 2FA code.
     *
     * Those are not password guesses, and holding the token already proves more than a
     * password does, so the attempt limit must not stand in their way. Otherwise a
     * locked out admin has no route back in at all until the window expires.
     *
     * @param $status bool
     * @return void
     */
    public static function setTokenVerifiedLogin($status = true)
    {
        self::$tokenVerifiedLogin = (bool)$status;
    }

    /**
     * @return bool
     */
    public static function isTokenVerifiedLogin()
    {
        return self::$tokenVerifiedLogin;
    }

    public static function getAuthSettings()
    {
        if (self::$authSettings) {
            return self::$authSettings;
        }

        $settings = &self::$authSettings;

        $defaults = [
            'disable_xmlrpc'          => 'no',
            'disable_app_login'       => 'no',
            'login_try_limit'         => 5,
            'login_try_timing'        => 30,
            'disable_users_rest'      => 'no',
            'secure_signup_form'      => 'yes',
            'notification_user_roles' => [],
            'notify_on_blocked'       => 'no',
            'notification_email'      => '{admin_email}',
            'auto_delete_logs_day'    => 30, // in days
            'digest_summary'          => '',
            'magic_login'             => 'no',
            'magic_restricted_roles'  => [],
            'magic_link_primary'      => 'no',
            'email2fa'                => 'no',
            'email2fa_roles'          => ['administrator', 'editor', 'author'],
            'totp_2fa'                => 'no',
            // Roles that may set up an authenticator app. Empty means none of them can.
            'totp_2fa_roles'          => [],
            // Roles that must have one before they can use the admin area.
            'totp_required_roles'     => [],
            'disable_admin_bar'       => 'no',
            'disable_bar_roles'       => [
                'subscriber'
            ],
            'trusted_proxies'         => '',
            'proxy_ip_header'         => ''
        ];

        $settings = get_option('__fls_auth_settings');

        if (!$settings || !is_array($settings)) {
            $defaults['require_configuration'] = 'yes';
            $defaults['digest_summary'] = 'monthly';
            $settings = $defaults;
            return $settings;
        }

        $settings = wp_parse_args($settings, $defaults);
        return $settings;
    }

    /**
     * What this plugin thinks a well configured site looks like.
     *
     * The one place that says so. "Apply recommended" writes this map over the saved
     * settings, and the dashboard's security checklist scores a site against the same map,
     * so a recommendation cannot be made in one place and contradicted in the other -
     * which is what happened when each of them carried its own copy.
     *
     * Two kinds of setting are deliberately absent, and both would do harm if added:
     *
     * - Ones with no right answer for every site. Blocking application passwords is sound
     *   hardening where nothing connects over the REST API and breaks every integration
     *   where something does; the same goes for anything else a site may legitimately
     *   depend on. Being absent here means "apply recommended" leaves it alone rather than
     *   undoing a deliberate choice, and the checklist does not score it.
     * - Ones that describe the server rather than a preference - trusted proxies, the
     *   forwarded-IP header - and ones that lock people out if imposed, like the roles
     *   required to have an authenticator app.
     *
     * @return array
     */
    public static function getRecommendedSettings()
    {
        return apply_filters('fluent_auth/recommended_settings', [
            'disable_xmlrpc'          => 'yes',
            'disable_users_rest'      => 'yes',
            'secure_signup_form'      => 'yes',
            'login_try_limit'         => 5,
            'login_try_timing'        => 30,
            'auto_delete_logs_day'    => 30,
            'notification_user_roles' => ['administrator', 'editor', 'author'],
            'notification_email'      => '{admin_email}',
            'notify_on_blocked'       => 'no',
            'magic_login'             => 'no',
            'magic_restricted_roles'  => [],
            'magic_link_primary'      => 'no',
            'email2fa'                => 'yes',
            'email2fa_roles'          => ['administrator', 'editor', 'author'],
            'totp_2fa'                => 'yes',
            /*
             * Offered to the roles that can change the site, matching the email codes
             * above. An empty list here would switch the method on for nobody, which is
             * a recommendation that reads as done and protects no one.
             *
             * Offering it is all this does. Which roles must have one stays absent for
             * the reason given above: imposing that locks people out.
             */
            'totp_2fa_roles'          => ['administrator', 'editor', 'author'],
            'disable_bar_roles'       => ['subscriber']
        ]);
    }

    /**
     * Names for the `media` a login came through.
     *
     * The column stores the internal handle - `web`, `totp`, `magic_login`, or whichever
     * social provider was used - and two screens show it: the logs table and the dashboard's
     * breakdown of how people signed in. One map, so they cannot name the same thing
     * differently. Anything not listed is titled from its own handle rather than hidden,
     * because an integration may add its own.
     *
     * @param string $media
     * @return string
     */
    public static function getLoginMediaLabel($media)
    {
        $media = $media ?: 'web';

        $labels = apply_filters('fluent_auth/login_media_labels', [
            'web'         => __('Login form', 'fluent-security'),
            'magic_login' => __('Magic link', 'fluent-security'),
            'email_2fa'   => __('Email code', 'fluent-security'),
            'totp'        => __('Authenticator app', 'fluent-security'),
            'app_password' => __('Application password', 'fluent-security'),
            'google'      => __('Google', 'fluent-security'),
            'github'      => __('GitHub', 'fluent-security'),
            'facebook'    => __('Facebook', 'fluent-security')
        ]);

        if (isset($labels[$media])) {
            return $labels[$media];
        }

        return ucwords(str_replace('_', ' ', $media));
    }

    public static function getAppPermission()
    {
        return apply_filters('fluent_auth/app_permission', 'manage_options');
    }

    public static function getUserRoles($keyed = false)
    {
        if (!function_exists('get_editable_roles')) {
            require_once(ABSPATH . 'wp-admin/includes/user.php');
        }

        $roles = \get_editable_roles();
        $formattedRoles = [];
        foreach ($roles as $roleKey => $role) {
            if ($keyed) {
                $formattedRoles[$roleKey] = $role['name'];
            } else {
                $formattedRoles[] = [
                    'id'    => $roleKey,
                    'title' => $role['name']
                ];
            }
        }
        return $formattedRoles;
    }

    public static function getLowLevelRoles()
    {
        if (!function_exists('get_editable_roles')) {
            require_once(ABSPATH . 'wp-admin/includes/user.php');
        }

        $roles = \get_editable_roles();

        $formattedRoles = [];

        foreach ($roles as $roleKey => $role) {
            if (!Arr::get($role, 'capabilities.publish_posts')) {
                $formattedRoles[$roleKey] = $role['name'];
            }
        }

        return apply_filters('fluent_auth/low_level_user_roles', $formattedRoles, $roles);
    }

    public static function getWpPermissions($keyed = false)
    {
        $allCaps = [];
        if (!function_exists('get_editable_roles')) {
            require_once(ABSPATH . 'wp-admin/includes/user.php');
        }

        $roles = \get_editable_roles();
        foreach ($roles as $role) {
            $allCaps = array_merge((array)$allCaps, (array)$role['capabilities']);
        }

        $formattedCaps = [];
        foreach ($allCaps as $capName => $cap) {
            if (!$capName) {
                continue;
            }
            if ($keyed) {
                $formattedCaps[$capName] = $capName;
            } else {
                $formattedCaps[] = [
                    'id'    => $capName,
                    'title' => $capName
                ];
            }
        }

        return $formattedCaps;
    }

    /**
     * The auth log is not an optional extra, it is what every protection here runs on:
     * the attempt limit counts failed rows, the account challenge counts them per user,
     * and the trusted IP exemption reads successful ones. Switching it off does not
     * trade logging for something else, it turns the plugin off.
     *
     * So there is no setting for it. A site with a genuine reason - another WAF already
     * doing this, a staging clone - can still opt out in code:
     *
     *     add_filter('fluent_auth/login_security_enabled', '__return_false');
     *
     * @return bool
     */
    public static function isLoginSecurityEnabled()
    {
        return (bool)apply_filters('fluent_auth/login_security_enabled', true);
    }

    public static function getSetting($key, $default = false)
    {
        $config = self::getAuthSettings();
        if (isset($config[$key])) {
            return $config[$key];
        }

        return $default;
    }

    public static function getIp($anonymize = false)
    {
        if (self::$resolvedIp === null) {
            self::$resolvedIp = self::resolveIp();
        }

        if ($anonymize) {
            return wp_privacy_anonymize_ip(self::$resolvedIp);
        }

        return self::$resolvedIp;
    }

    /**
     * Works out who the visitor is, trusting a forwarded header only where the
     * connection itself proves it came from a proxy we know about.
     *
     * Order matters: REMOTE_ADDR is the only value a client cannot forge, so anything
     * that overrides it has to earn that right first.
     *
     * @return string
     */
    private static function resolveIp()
    {
        $remoteAddr = '';
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $remoteAddr = self::stripPort(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])));
        }

        if (!$remoteAddr) {
            // No connection behind this request, eg WP-CLI or cron.
            return apply_filters('fluent_auth/user_ip', '127.0.0.1');
        }

        $ipAddress = '';

        /*
         * 1. Cloudflare. The header is only worth anything once we know the connection
         *    actually came from a Cloudflare edge, so the range check comes first.
         */
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && self::isCfIp($remoteAddr)) {
            $candidate = self::stripPort(sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP'])));
            if (rest_is_ip_address($candidate)) {
                $ipAddress = $candidate;
            }
        }

        /*
         * 2. A reverse proxy the site owner has declared. Never inferred - guessing
         *    from REMOTE_ADDR is exactly what lets a client name its own address.
         */
        if (!$ipAddress && self::isTrustedProxy($remoteAddr)) {
            $header = self::getProxyIpHeader();
            if ($header && !empty($_SERVER[$header])) {
                $ipAddress = self::clientFromForwardedChain(
                    sanitize_text_field(wp_unslash($_SERVER[$header]))
                );
            }
        }

        // 3. The connection itself.
        if (!$ipAddress) {
            $ipAddress = $remoteAddr;
        }

        return apply_filters('fluent_auth/user_ip', $ipAddress);
    }

    /**
     * Picks the visitor out of an X-Forwarded-For style list.
     *
     * The list reads client, proxy1, proxy2..., and anything to the left of our own
     * proxies was supplied by whoever connected. So we walk in from the right and stop
     * at the first address that is not one of ours.
     *
     * @param $value string
     * @return string
     */
    private static function clientFromForwardedChain($value)
    {
        $parts = array_reverse(array_filter(array_map('trim', explode(',', $value))));

        foreach ($parts as $part) {
            $part = self::stripPort($part);

            if (!rest_is_ip_address($part)) {
                continue;
            }

            if (self::isTrustedProxy($part)) {
                continue;
            }

            return $part;
        }

        return '';
    }

    /**
     * @param $ip string
     * @return bool
     */
    public static function isTrustedProxy($ip)
    {
        foreach (self::getTrustedProxies() as $range) {
            if (self::ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Trusted proxy addresses / CIDR ranges.
     *
     * A wp-config.php constant wins over the settings screen: server topology is a
     * sysadmin concern, and a constant cannot be flipped by a compromised admin login.
     *
     * @return array
     */
    public static function getTrustedProxies()
    {
        if (self::$trustedProxies !== null) {
            return self::$trustedProxies;
        }

        if (defined('FLUENT_AUTH_TRUSTED_PROXIES') && FLUENT_AUTH_TRUSTED_PROXIES) {
            $raw = FLUENT_AUTH_TRUSTED_PROXIES;
        } else {
            $raw = self::getSetting('trusted_proxies', '');
        }

        $proxies = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', (string)$raw))));

        self::$trustedProxies = (array)apply_filters('fluent_auth/trusted_proxies', $proxies);

        return self::$trustedProxies;
    }

    /**
     * The $_SERVER key the declared proxy passes the visitor IP in.
     *
     * @return string
     */
    public static function getProxyIpHeader()
    {
        if (defined('FLUENT_AUTH_PROXY_IP_HEADER') && FLUENT_AUTH_PROXY_IP_HEADER) {
            $header = FLUENT_AUTH_PROXY_IP_HEADER;
        } else {
            $header = self::getSetting('proxy_ip_header', '');
        }

        if (!$header) {
            $header = 'HTTP_X_FORWARDED_FOR';
        }

        $header = strtoupper(str_replace('-', '_', trim((string)$header)));

        if (strpos($header, 'HTTP_') !== 0) {
            $header = 'HTTP_' . $header;
        }

        return $header;
    }

    /**
     * Drops a trailing port, for both 1.2.3.4:56 and [::1]:56 forms.
     *
     * @param $ip string
     * @return string
     */
    private static function stripPort($ip)
    {
        $ip = trim((string)$ip);

        if (preg_match('/^\[(.+)\](?::\d+)?$/', $ip, $matches)) {
            return $matches[1];
        }

        if (preg_match('/^(\d+\.\d+\.\d+\.\d+):\d+$/', $ip, $matches)) {
            return $matches[1];
        }

        return $ip;
    }

    public static function loadView($template, $data)
    {
        extract($data, EXTR_OVERWRITE);

        $template = sanitize_file_name($template);
        $template = str_replace('.', DIRECTORY_SEPARATOR, $template);

        $path = FLUENT_AUTH_PLUGIN_PATH . 'app/Views/' . $template . '.php';

        if (!file_exists($path)) {
            return '';
        }

        ob_start();
        include $path;
        return ob_get_clean();
    }

    public static function cleanUpLogs()
    {
        $oldDays = self::getSetting('auto_delete_logs_day');

        if (!$oldDays) {
            return;
        }

        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $oldDays * 86400);

        flsDb()->table('fls_auth_logs')
            ->where('created_at', '<', $dateTime)
            ->delete();

        if ($oldDays < 30) {
            $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - 30 * 86400);
        }

        flsDb()->table('fls_login_hashes')
            ->where('valid_till', '<', current_time('mysql'))
            ->where('status', 'issued')
            ->update([
                'status' => 'expired'
            ]);

        flsDb()->table('fls_login_hashes')
            ->where('status', '!=', 'issued')
            ->where('created_at', '<', $dateTime)
            ->delete();

    }

    public static function getSocialAuthSettings($context = 'view')
    {
        if (self::$socialAuthSettings) {
            return self::$socialAuthSettings;
        }

        $settings = &self::$socialAuthSettings;

        $defaults = [
            'enabled'                => 'no',
            'enable_google'          => 'no',
            'google_key_method'      => 'wp_config',
            'google_client_id'       => '',
            'google_one_tap'         => 'no',
            'google_client_secret'   => '',
            'enable_github'          => 'no',
            'github_key_method'      => 'wp_config',
            'github_client_id'       => '',
            'github_client_secret'   => '',
            'enable_facebook'        => 'no',
            'facebook_key_method'    => 'wp_config',
            'facebook_client_id'     => '',
            'facebook_client_secret' => '',
            'facebook_api_version'   => 'v12.0',
            'enable_linkedin'        => 'no',
            'linkedin_key_method'    => 'wp_config',
            'linkedin_client_id'     => '',
            'linkedin_client_secret' => ''
        ];

        $settings = get_option('__fls_social_auth_settings');

        if (!$settings || !is_array($settings)) {
            $settings = $defaults;
            return $settings;
        }

        $settings = wp_parse_args($settings, $defaults);

        if ($context == 'edit') {
            if ($settings['google_key_method'] == 'wp_config') {
                $settings['google_client_id'] = (defined('FLUENT_AUTH_GOOGLE_CLIENT_ID')) ? FLUENT_AUTH_GOOGLE_CLIENT_ID : '';
                $settings['google_client_secret'] = (defined('FLUENT_AUTH_GOOGLE_CLIENT_SECRET')) ? FLUENT_AUTH_GOOGLE_CLIENT_SECRET : '';
            }

            if ($settings['github_key_method'] == 'wp_config') {
                $settings['github_client_id'] = (defined('FLUENT_AUTH_GITHUB_CLIENT_ID')) ? FLUENT_AUTH_GITHUB_CLIENT_ID : '';
                $settings['github_client_secret'] = (defined('FLUENT_AUTH_GITHUB_CLIENT_SECRET')) ? FLUENT_AUTH_GITHUB_CLIENT_SECRET : '';
            }
            if ($settings['facebook_key_method'] == 'wp_config') {
                $settings['facebook_client_id'] = (defined('FLUENT_AUTH_FACEBOOK_CLIENT_ID')) ? FLUENT_AUTH_FACEBOOK_CLIENT_ID : '';
                $settings['facebook_client_secret'] = (defined('FLUENT_AUTH_FACEBOOK_CLIENT_SECRET')) ? FLUENT_AUTH_FACEBOOK_CLIENT_SECRET : '';
                $settings['facebook_api_version'] = sanitize_text_field($settings['facebook_api_version']);
            }

            if ($settings['linkedin_key_method'] == 'wp_config') {
                $settings['linkedin_client_id'] = (defined('FLUENT_AUTH_LINKEDIN_CLIENT_ID')) ? FLUENT_AUTH_LINKEDIN_CLIENT_ID : '';
                $settings['linkedin_client_secret'] = (defined('FLUENT_AUTH_LINKEDIN_CLIENT_SECRET')) ? FLUENT_AUTH_LINKEDIN_CLIENT_SECRET : '';
            }
        }

        return $settings;
    }

    public static function getAuthFormsSettings()
    {
        $settingsDefault = [
            'enabled'                 => 'no',
            'login_redirects'         => 'no',
            'default_login_redirect'  => '',
            'default_logout_redirect' => '',
            'redirect_rules'          => []
        ];

        $settings = get_option('__fls_auth_forms_settings', []);

        if (!$settings) {
            return $settingsDefault;
        }

        return wp_parse_args($settings, $settingsDefault);
    }

    public static function setLoginMedia($media)
    {
        self::$loginMedia = $media;
    }

    public static function getLoginMedia()
    {
        if (self::$loginMedia) {
            return self::$loginMedia;
        }

        return 'web';
    }

    /**
     * Cloudflare's published edge ranges.
     *
     * The v6 list matters as much as the v4 one: Cloudflare reaches origins over IPv6
     * wherever they answer on it, and an unrecognised edge means every visitor behind
     * it collapses onto a single address.
     *
     * @see https://www.cloudflare.com/ips/
     * @return array
     */
    public static function getCloudflareIpRanges()
    {
        $ranges = [
            // IPv4
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/13',
            '131.0.72.0/22',
            // IPv6
            '2400:cb00::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            '2405:b500::/32',
            '2405:8100::/32',
            '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];

        // Filterable so a range change does not have to wait for a plugin release.
        return (array)apply_filters('fluent_auth/cloudflare_ip_ranges', $ranges);
    }

    public static function isCfIp($ip = '')
    {
        if (!$ip && !empty($_SERVER['REMOTE_ADDR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        $ip = self::stripPort($ip);

        if (!$ip) {
            return false;
        }

        foreach (self::getCloudflareIpRanges() as $range) {
            if (self::ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * CIDR / exact match that understands both IPv4 and IPv6.
     *
     * Works on the packed binary form, because ip2long() - what this used to rely on -
     * simply returns false for any IPv6 address.
     *
     * Public because the trusted proxy list is no longer the only thing matching an
     * address against a range - the IP allow and block lists do the same, and a second
     * implementation of CIDR matching is the last thing a security plugin needs.
     *
     * @param $ip string
     * @param $range string
     * @return bool
     */
    public static function ipInRange($ip, $range)
    {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        list($subnet, $bits) = explode('/', $range, 2);

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        // false on malformed input, differing lengths means v4 against v6.
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bits = (int)$bits;
        $maxBits = strlen($ipBin) * 8;

        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        if ($wholeBytes && strncmp($ipBin, $subnetBin, $wholeBytes) !== 0) {
            return false;
        }

        if ($remainingBits) {
            $mask = chr((0xFF << (8 - $remainingBits)) & 0xFF);
            if ((($ipBin[$wholeBytes] ^ $subnetBin[$wholeBytes]) & $mask) !== "\0") {
                return false;
            }
        }

        return true;
    }

    public static function getAuthCustomizerSettings()
    {

        $siteTitle = get_bloginfo('name');
        // get site logo
        $siteLogo = '';

        $tagLine = get_bloginfo('description');

        $defaults = [
            'status' => 'no',
            'login'  => [
                'banner' => [
                    'hidden'           => false,
                    'type'             => 'banner',
                    'position'         => 'left',
                    'logo'             => $siteLogo,
                    'title'            => 'Welcome to ' . $siteTitle,
                    'description'      => $tagLine,
                    'title_color'      => '#19283a',
                    'text_color'       => '#525866',
                    'background_image' => '',
                    'background_color' => '#F5F7FA'
                ],
                'form'   => [
                    'type'               => 'form',
                    'position'           => 'right',
                    'title'              => 'Login to ' . $siteTitle,
                    'description'        => 'Please enter your details to login',
                    'title_color'        => '#19283a',
                    'text_color'         => '#525866',
                    'button_label'       => 'Login',
                    'button_color'       => '#2B2E33',
                    'button_label_color' => '#ffffff',
                    'background_image'   => '',
                    'background_color'   => '#ffffff'
                ]
            ],
            'signup' => [
                'banner' => [
                    'hidden'           => false,
                    'type'             => 'banner',
                    'position'         => 'left',
                    'logo'             => $siteLogo,
                    'title'            => 'Welcome to ' . $siteTitle,
                    'description'      => $tagLine,
                    'title_color'      => '#19283a',
                    'text_color'       => '#525866',
                    'background_image' => '',
                    'background_color' => '#F5F7FA',
                ],
                'form'   => [
                    'type'               => 'form',
                    'position'           => 'right',
                    'title'              => 'Sign Up to ' . $siteTitle,
                    'description'        => 'Please enter your details to register',
                    'button_label'       => 'Sign up',
                    'terms_label'        => '',
                    'title_color'        => '#19283a',
                    'text_color'         => '#525866',
                    'button_color'       => '#2B2E33',
                    'button_label_color' => '#ffffff',
                    'background_image'   => '',
                    'background_color'   => '#ffffff',
                ]
            ]
        ];

        $settings = get_option('__fls_auth_customizer_settings', []);

        if (!$settings) {
            return $defaults;
        }

        $settings = wp_parse_args($settings, $defaults);

        return $settings;
    }


    public static function formatAuthCustomizerSettings($settingFields)
    {
        $textFields = ['type', 'title', 'button_label', 'position', 'title_color', 'text_color', 'button_color', 'button_label_color', 'background_color'];
        $mediaFields = ['logo', 'background_image'];

        $formattedFields = [];
        foreach ($settingFields as $section => $settings) {
            if (is_string($settings)) {
                $formattedFields[$section] = sanitize_text_field($settings);
                continue;
            }

            foreach ($settings as $key => $setting) {
                $textValues = array_map('sanitize_text_field', Arr::only($setting, $textFields));
                $mediaUrls = array_map('sanitize_url', Arr::only($setting, $mediaFields));
                $formattedField = array_merge($textValues, $mediaUrls);
                $formattedField['description'] = wp_kses_post(Arr::get($setting, 'description'));
                $formattedField['hidden'] = Arr::isTrue($setting, 'hidden');
                $formattedFields[$section][$key] = $formattedField;
            }
        }

        return $formattedFields;
    }

    public static function getValidatedRedirectUrl($location, $fallback = '')
    {
        $validated = wp_validate_redirect($location, $fallback);

        if ($validated !== $location) {
            return apply_filters('fluent_auth/validated_redirect', $validated, $location, $fallback);
        }

        return $validated;
    }
}
