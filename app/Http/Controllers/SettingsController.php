<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class SettingsController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        return [
            'settings' => Helper::getAuthSettings(),
            'user_roles' => Helper::getUserRoles(),
            'low_level_roles' => Helper::getLowLevelRoles()
        ];
    }

    public static function updateSettings(\WP_REST_Request $request)
    {
        $settings = self::validateSettings($request->get_param('settings'));
        if (is_wp_error($settings)) {
            return $settings;
        }

        update_option('__fls_auth_settings', $settings);

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
                $settings[$settingKey] = (int) $setting;
            } else {
                if(is_array($setting)) {
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

            if( $settings['email2fa'] == 'yes' && empty($settings['email2fa_roles'])) {
                $errors['email2fa_roles'] = [
                    'required' => 'Two-Factor Authentication roles is required'
                ];
            }

        } else {
            $settings['magic_login'] = 'no';
            $settings['email2fa'] = 'no';
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
            'settings' => $settings,
            'roles'    => Helper::getUserRoles(true),
            'user_capabilities' => Helper::getWpPermissions(true)
        ];
    }

    public static function saveAuthFormSettings(\WP_REST_Request $request)
    {
        $oldSettings = Helper::getAuthFormsSettings();
        $settings = $request->get_param('settings');

        if (!$settings) {
            $settings = $request->get_param('redirect_settings');

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

        update_option('__fls_auth_forms_settings', $oldSettings, 'no');

        return [
            'message'  => __('Settings has been updated', 'fluent-security'),
            'settings' => $oldSettings
        ];
    }

    public static function getAuthCustomizerSetting(\WP_REST_Request $request)
    {
        return [
            'settings' => Helper::getAuthCustomizerSettings(),
            'login_form_html' => ''
        ];
    }
}
