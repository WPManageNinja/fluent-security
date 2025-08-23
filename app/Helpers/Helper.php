<?php

namespace FluentAuth\App\Helpers;

class Helper
{
    private static $loginMedia = 'web';

    public static function getAuthSettings()
    {
        static $settings;
        if ($settings) {
            return $settings;
        }

        $defaults = [
            'disable_xmlrpc'          => 'no',
            'disable_app_login'       => 'no',
            'enable_auth_logs'        => 'yes',
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
            'disable_admin_bar'       => 'no',
            'disable_bar_roles'       => [
                'subscriber'
            ]
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
        static $ipAddress;

        if ($ipAddress) {
            return $ipAddress;
        }

        if (empty($_SERVER['REMOTE_ADDR'])) {
            // It's a local cli request
            return '127.0.0.1';
        }

        $ipAddress = '';
        if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
            //If it's a valid Cloudflare request
            if (self::isCfIp($_SERVER['REMOTE_ADDR'])) {
                //Use the CF-Connecting-IP header.
                $ipAddress = $_SERVER['HTTP_CF_CONNECTING_IP'];
            } else {
                //If it isn't valid, then use REMOTE_ADDR.
                $ipAddress = $_SERVER['REMOTE_ADDR'];
            }
        } else if ($_SERVER['REMOTE_ADDR'] == '127.0.0.1') {
            // most probably it's local reverse proxy
            if (isset($_SERVER["HTTP_CLIENT_IP"])) {
                $ipAddress = $_SERVER["HTTP_CLIENT_IP"];
            } else if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $ipAddress = (string)rest_is_ip_address(trim(current(preg_split('/,/', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']))))));
            }
        }

        if (!$ipAddress) {
            $ipAddress = $_SERVER['REMOTE_ADDR'];
        }

        $ipAddress = preg_replace('/^(\d+\.\d+\.\d+\.\d+):\d+$/', '\1', $ipAddress);

        $ipAddress = apply_filters('fluent_auth/user_ip', $ipAddress);

        if ($anonymize) {
            return wp_privacy_anonymize_ip($ipAddress);
        }

        $ipAddress = sanitize_text_field(wp_unslash($ipAddress));

        return $ipAddress;
    }

    public static function loadView($template, $data)
    {
        extract($data, EXTR_OVERWRITE);

        $template = sanitize_file_name($template);

        $template = str_replace('.', DIRECTORY_SEPARATOR, $template);

        ob_start();
        include FLUENT_AUTH_PLUGIN_PATH . 'app/Views/' . $template . '.php';
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
        static $settings;
        if ($settings) {
            return $settings;
        }

        $defaults = [
            'enabled'                => 'no',
            'enable_google'          => 'no',
            'google_key_method'      => 'wp_config',
            'google_client_id'       => '',
            'google_client_secret'   => '',
            'enable_github'          => 'no',
            'github_key_method'      => 'wp_config',
            'github_client_id'       => '',
            'github_client_secret'   => '',
            'enable_facebook'        => 'no',
            'facebook_key_method'    => 'wp_config',
            'facebook_client_id'     => '',
            'facebook_client_secret' => '',
            'facebook_api_version'   => 'v12.0'
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

    public static function isCfIp($ip = '')
    {
        if (!$ip) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        $cloudflareIPRanges = array(
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
        );
        $validCFRequest = false;
        //Make sure that the request came via Cloudflare.
        foreach ($cloudflareIPRanges as $range) {
            //Use the ip_in_range function from Joomla.
            if (self::ipInRange($ip, $range)) {
                //IP is valid. Belongs to Cloudflare.
                return true;
            }
        }

        return false;
    }

    private static function ipInRange($ip, $range)
    {
        if (strpos($range, '/') !== false) {
            // $range is in IP/NETMASK format
            list($range, $netmask) = explode('/', $range, 2);
            if (strpos($netmask, '.') !== false) {
                // $netmask is a 255.255.0.0 format
                $netmask = str_replace('*', '0', $netmask);
                $netmask_dec = ip2long($netmask);
                return ((ip2long($ip) & $netmask_dec) == (ip2long($range) & $netmask_dec));
            } else {
                // $netmask is a CIDR size block
                // fix the range argument
                $x = explode('.', $range);
                while (count($x) < 4) $x[] = '0';
                list($a, $b, $c, $d) = $x;
                $range = sprintf("%u.%u.%u.%u", empty($a) ? '0' : $a, empty($b) ? '0' : $b, empty($c) ? '0' : $c, empty($d) ? '0' : $d);
                $range_dec = ip2long($range);
                $ip_dec = ip2long($ip);

                # Strategy 1 - Create the netmask with 'netmask' 1s and then fill it to 32 with 0s
                #$netmask_dec = bindec(str_pad('', $netmask, '1') . str_pad('', 32-$netmask, '0'));

                # Strategy 2 - Use math to create it
                /** @phpstan-ignore binaryOp.invalid */
                $wildcard_dec = pow(2, (32 - $netmask)) - 1;
                $netmask_dec = ~$wildcard_dec;

                return (($ip_dec & $netmask_dec) == ($range_dec & $netmask_dec));
            }
        } else {
            // range might be 255.255.*.* or 1.2.3.0-1.2.3.255
            if (strpos($range, '*') !== false) { // a.b.*.* format
                // Just convert to A-B format by setting * to 0 for A and 255 for B
                $lower = str_replace('*', '0', $range);
                $upper = str_replace('*', '255', $range);
                $range = "$lower-$upper";
            }

            if (strpos($range, '-') !== false) { // A-B format
                list($lower, $upper) = explode('-', $range, 2);
                $lower_dec = (float)sprintf("%u", ip2long($lower));
                $upper_dec = (float)sprintf("%u", ip2long($upper));
                $ip_dec = (float)sprintf("%u", ip2long($ip));
                return (($ip_dec >= $lower_dec) && ($ip_dec <= $upper_dec));
            }
            return false;
        }
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

        if($validated !== $location) {
            return apply_filters('fluent_auth/validated_redirect', $validated, $location, $fallback);
        }

        return $validated;
    }
}
