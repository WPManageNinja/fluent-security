<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\ServerModeHandler;

class SettingsController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        return [
            'settings'        => Helper::getAuthSettings(),
            'user_roles'      => Helper::getUserRoles(),
            'low_level_roles' => Helper::getLowLevelRoles()
        ];
    }

    public static function updateSettings(\WP_REST_Request $request)
    {
        $settings = self::validateSettings($request->get_param('settings'));
        if (is_wp_error($settings)) {
            return $settings;
        }

        update_option('__fls_auth_settings', $settings, false);

        return [
            'settings' => $settings,
            'message'  => __('Settings has been updated', 'fluent-security')
        ];
    }

    private static function validateSettings($settings)
    {
        $oldSettings = Helper::getAuthSettings();
        if (isset($settings['require_configuration'])) {
            unset($settings['require_configuration']);
        }

        $settings = Arr::only($settings, array_keys($oldSettings));

        $numericTypes = [
            'auto_delete_logs_day',
            'login_try_limit',
            'login_try_timing'
        ];

        foreach ($settings as $settingKey => $setting) {
            if (in_array($settingKey, $numericTypes)) {
                $settings[$settingKey] = (int)$setting;
            } else {
                if (is_array($setting)) {
                    $settings[$settingKey] = map_deep($setting, 'sanitize_text_field');
                } else {
                    $settings[$settingKey] = sanitize_text_field($setting);
                }
            }
        }

        $errors = [];

        if ($settings['enable_auth_logs'] == 'yes') {
            if (!$settings['login_try_limit']) {
                $errors['login_try_limit'] = [
                    'required' => 'Login try limit is required'
                ];
            }
            if (!$settings['login_try_timing']) {
                $errors['login_try_timing'] = [
                    'required' => 'Login Timing is required'
                ];
            }
        }

        if ($settings['email2fa'] == 'yes' && empty($settings['email2fa_roles'])) {
            $errors['email2fa_roles'] = [
                'required' => 'Two-Factor Authentication roles is required'
            ];
        }

        if ($errors) {
            return new \WP_Error('validation_error', 'Form Validation failed', $errors);
        }

        return $settings;

    }


    public static function getAuthFormSettings(\WP_REST_Request $request)
    {

        $settings = Helper::getAuthFormsSettings();

        return [
            'settings'          => $settings,
            'roles'             => Helper::getUserRoles(true),
            'user_capabilities' => Helper::getWpPermissions(true)
        ];
    }

    public static function saveAuthFormSettings(\WP_REST_Request $request)
    {
        $oldSettings = Helper::getAuthFormsSettings();
        $settings = (array) $request->get_param('settings');

        if (!$settings) {
            $settings = (array) $request->get_param('redirect_settings');

            $oldSettings['login_redirects'] = sanitize_text_field($settings['login_redirects']);

            if (!empty($settings['default_login_redirect'])) {
                $oldSettings['default_login_redirect'] = sanitize_url($settings['default_login_redirect']);
            }

            if (!empty($settings['default_logout_redirect'])) {
                $oldSettings['default_logout_redirect'] = sanitize_url($settings['default_logout_redirect']);
            }

            $redirectRules = Arr::get($settings, 'redirect_rules', []);

            $sanitizedRules = [];

            if ($redirectRules) {
                foreach ($redirectRules as $redirectIndex => $redirect) {
                    $item = [
                        'login'  => '',
                        'logout' => ''
                    ];
                    if (!empty($redirect['login'])) {
                        $item['login'] = sanitize_url($redirect['login']);
                    }
                    if (!empty($redirect['logout'])) {
                        $item['logout'] = sanitize_url($redirect['logout']);
                    }
                    $conditions = $redirect['conditions'];
                    foreach ($conditions as $index => $condition) {
                        $conditions[$index] = map_deep($condition, 'sanitize_text_field');
                    }

                    $item['conditions'] = $conditions;

                    $sanitizedRules[] = $item;
                }
            }

            $oldSettings['redirect_rules'] = $sanitizedRules;

        } else {
            $oldSettings['enabled'] = sanitize_text_field($settings['enabled']);
        }

        update_option('__fls_auth_forms_settings', $oldSettings, false);

        return [
            'message'  => __('Settings has been updated', 'fluent-security'),
            'settings' => $oldSettings
        ];
    }

    public static function getAuthCustomizerSetting(\WP_REST_Request $request)
    {
        return [
            'settings'        => Helper::getAuthCustomizerSettings(),
            'login_form_html' => ''
        ];
    }

    public static function saveAuthCustomizerSetting(\WP_REST_Request $request)
    {
        $settings = (array) $request->get_param('settings');
        $settings = Helper::formatAuthCustomizerSettings($settings);
        update_option('__fls_auth_customizer_settings', $settings, false);

        return [
            'message'  => __('Settings has been updated', 'fluent-security'),
            'settings' => $settings
        ];
    }

    public static function uploadImage(\WP_REST_Request $request)
    {
        $file = $_FILES['file'];
        if (empty($file)) {
            return new \WP_Error('invalid_file', __('Invalid file', 'fluent-security'));
        }

        // wp_check_filetype_and_ext() will look at both the file extension and the file's actual contents.
        $checked = wp_check_filetype_and_ext(
            $file['tmp_name'],
            $file['name'],
            null // we’ll supply our own list of allowed types below
        );
        $ext = $checked['ext'];
        $type = $checked['type'];


        $allowed_mimes = [
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png'          => 'image/png',
            'gif'          => 'image/gif',
            'webp'         => 'image/webp',
            'bmp'          => 'image/bmp',
            'svg'          => 'image/svg+xml',
        ];

        if (!in_array($type, $allowed_mimes, true)) {
            return new \WP_Error(
                'invalid_file_type',
                __('Sorry, you can only upload JPG, PNG, GIF, WebP, BMP or SVG files.', 'fluent-security')
            );
        }

        if (!function_exists('wp_handle_upload')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $upload_overrides = [
            'test_form' => false,
            // Pass the allowed list here so WP also enforces it
            'mimes'     => $allowed_mimes,
        ];
        $movefile = wp_handle_upload($file, $upload_overrides);

        if (isset($movefile['error'])) {
            return new \WP_Error('upload_error', $movefile['error']);
        }

        return [
            'media' => $movefile,
        ];
    }


    public static function saveChildSite(\WP_REST_Request $request)
    {
        if (!(new ServerModeHandler())->isEnabled()) {
            return new \WP_Error('invalid_request', __('This feature is only available in the server mode.', 'fluent-security'));
        }
        $willRemove = $request->get_param('will_remove');
        if ($willRemove == 'yes') {
            $url = $request->get_param('site_url');

            $prevSettings = get_option('__fls_child_sites', []);

            $prevSettings = array_filter($prevSettings, function ($site) use ($url) {
                return $site['site_url'] !== $url;
            });

            update_option('__fls_child_sites', $prevSettings, false);

            return [
                'message' => __('Site has been removed successfully', 'fluent-security')
            ];
        }

        $siteConfig = trim($request->get_param('site_config'));

        if (empty($siteConfig)) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'));
        }

        $siteConfig = json_decode($siteConfig, true);

        if (empty($siteConfig['site_url']) || empty($siteConfig['callback_url'])) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'));
        }

        // validate the urls
        if (!filter_var($siteConfig['site_url'], FILTER_VALIDATE_URL)) {
            return new \WP_Error('invalid_request', __('Invalid site URL', 'fluent-security'));
        }
        if (!filter_var($siteConfig['callback_url'], FILTER_VALIDATE_URL)) {
            return new \WP_Error('invalid_request', __('Invalid callback URL', 'fluent-security'));
        }

        $fomattedData = [
            'site_url'     => sanitize_url($siteConfig['site_url']),
            'callback_url' => sanitize_url($siteConfig['callback_url']),
            'title'        => sanitize_text_field($siteConfig['site_title']),
            'status'       => 'yes'
        ];

        if (empty($fomattedData['title'])) {
            $fomattedData['title'] = parse_url($fomattedData['site_url'], PHP_URL_HOST);
        }

        $previousSites = get_option('__fls_child_sites', []);

        $siteId = strtolower(wp_generate_password(4, false));

        while (isset($previousSites[$siteId])) {
            $siteId = strtolower(wp_generate_password(4, false));
        }

        $fomattedData['site_id'] = $siteId;

        // check if the site already exists
        $existingSite = array_filter($previousSites, function ($site) use ($fomattedData) {
            return $site['site_url'] === $fomattedData['site_url'];
        });

        if (!empty($existingSite)) {
            return new \WP_Error('invalid_request', __('This site already exists.', 'fluent-security'));
        }

        $fomattedData['secret_key'] = wp_generate_password(32, false);
        $previousSites[$fomattedData['site_id']] = $fomattedData;

        update_option('__fls_child_sites', $previousSites, false);

        $serverConfig = json_encode([
            'server_token' => $fomattedData['secret_key'],
            'callback'     => rest_url('fluent-auth/child-sites/validate-token'),
            'server_url'   => site_url(),
            'site_id'      => $fomattedData['site_id']
        ], JSON_UNESCAPED_SLASHES);

        return [
            'message'      => __('Site has been added successfully', 'fluent-security'),
            'server_token' => $serverConfig
        ];
    }

    public static function getChildSites(\WP_REST_Request $request)
    {

        if (!(new ServerModeHandler())->isEnabled()) {
            return new \WP_Error('invalid_request', __('This feature is only available in the server mode.', 'fluent-security'));
        }

        $sites = get_option('__fls_child_sites', []);

        $formattedSites = [];
        foreach ($sites as $site) {
            $formattedSites[] = [
                'title'   => $site['title'],
                'url'     => $site['site_url'],
                'site_id' => $site['site_id'],
            ];
        }

        return [
            'sites' => $formattedSites,
            'raw'   => $sites
        ];
    }

    public static function validateChildSiteToken(\WP_REST_Request $request)
    {

        $data = [
            'user_token'   => $request->get_param('user_token'),
            'server_token' => $request->get_param('server_token'),
            'site_id'      => $request->get_param('site_id'),
        ];

        if (empty($data['user_token']) || empty($data['server_token']) || empty($data['site_id'])) {
            return new \WP_Error('invalid_request', __('Invalid request', 'fluent-security'));
        }

        $sites = get_option('__fls_child_sites', []);
        $site = Arr::get($sites, $data['site_id'], null);
        if (empty($site)) {
            return new \WP_Error('invalid_request', __('Invalid Site ID', 'fluent-security'));
        }

        if ($site['secret_key'] !== $data['server_token']) {
            return new \WP_Error('invalid_request', __('Invalid server token', 'fluent-security'));
        }

        $userToken = explode('___', $data['user_token']);

        $userId = Arr::get($userToken, '1', null);

        if (!$userId) {
            return new \WP_Error('invalid_request', __('Invalid user token', 'fluent-security'));
        }

        $user = get_user_by('ID', $userId);
        $userMeta = get_user_meta($userId, '__flsc_temp_token', true);

        if (empty($user) || empty($userMeta) || $userMeta !== $data['user_token']) {
            return new \WP_Error('invalid_request', __('Invalid user token', 'fluent-security'));
        }

        //   update_user_meta($userId, '__flsc_temp_token', '', true);// we are making it empty to avoid re-login

        // now we will prepare the data for the user
        $data = apply_filters('fluent_auth/remote_auth_response_data', [
            'remote_user_id'  => $user->ID,
            'user_login'      => $user->user_login,
            'user_email'      => $user->user_email,
            'user_nicename'   => $user->user_nicename,
            'user_url'        => $user->user_url,
            'nickname'        => $user->nickname,
            'locale'          => $user->locale,
            'display_name'    => $user->display_name,
            'user_registered' => $user->user_registered,
            'roles'           => array_values($user->roles),
            'first_name'      => $user->first_name,
            'last_name'       => $user->last_name,
            'description'     => $user->description,
        ], $user, $site);

        return [
            'user_data' => $data,
        ];
    }
}
