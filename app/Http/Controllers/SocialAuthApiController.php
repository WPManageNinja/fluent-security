<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\FacebookAuthService;
use FluentAuth\App\Services\GithubAuthService;
use FluentAuth\App\Services\GoogleAuthService;

class SocialAuthApiController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        return [
            'settings'  => Helper::getSocialAuthSettings('view'),
            'auth_info' => [
                'github'   => [
                    'is_available'        => true,
                    'app_redirect'        => GithubAuthService::getAppRedirect(),
                    'has_wp_config_keys'  => self::hasWpConfigKeys('github'),
                    'doc_url'             => 'https://fluentauth.com/docs/github-auth-connection'
                ],
                'google'   => [
                    'is_available'        => true,
                    'app_redirect'        => GoogleAuthService::getAppRedirect(),
                    'has_wp_config_keys'  => self::hasWpConfigKeys('google'),
                    'doc_url'             => 'https://fluentauth.com/docs/google-auth-connection'
                ],
                'facebook' => [
                    'is_available'        => true,
                    'app_redirect'        => FacebookAuthService::getAppRedirect(),
                    'has_wp_config_keys'  => self::hasWpConfigKeys('facebook'),
                    'doc_url'             => 'https://fluentauth.com/docs/facebook-auth-connection'
                ]
            ]
        ];
    }

    /**
     * Whether this provider's credentials are sitting in wp-config.php.
     *
     * Only PHP can see a constant, so the screen is told whether the pair is there
     * rather than left to guess. It answers for the constants themselves whatever the
     * saved storage choice is - the radio can be moved without saving, and the answer
     * for where it now points should not depend on where it used to.
     *
     * Whether the client ID and secret are in the database is not reported: those are
     * in the form the screen is already holding, so it reads them there.
     */
    private static function hasWpConfigKeys($provider)
    {
        $prefix = 'FLUENT_AUTH_' . strtoupper($provider);

        foreach (['_CLIENT_ID', '_CLIENT_SECRET'] as $suffix) {
            if (!defined($prefix . $suffix) || !constant($prefix . $suffix)) {
                return false;
            }
        }

        return true;
    }

    public static function saveSettings(\WP_REST_Request $request)
    {
        $settings = self::validateSettings($request->get_param('settings'));
        if (is_wp_error($settings)) {
            return $settings;
        }

        update_option('__fls_social_auth_settings', $settings, false);

        return [
            'message' => 'Social login settings has been updated'
        ];
    }

    private static function validateSettings($settings)
    {
        /*
         * Turning social login off clears the stored credentials, which is right when it
         * is what was asked for and destructive when it is not. A payload that is not a
         * settings array cannot have asked for it - it is a request that went wrong, and
         * the one below would read a missing 'enabled' as "no" and wipe the client IDs
         * and secrets on the strength of it. Refuse instead.
         */
        if (!is_array($settings) || !isset($settings['enabled'])) {
            return new \WP_Error('invalid_settings', __('Social login settings are missing from this request', 'fluent-security'), ['status' => 400]);
        }

        $oldSettings = Helper::getSocialAuthSettings('view');
        $settings = Arr::only($settings, array_keys($oldSettings));

        if ($settings['enabled'] != 'yes' || ($settings['enable_google'] != 'yes' && $settings['enable_github'] != 'yes' &&
                $settings['enable_facebook'] != 'yes')) {
            return [
                'enabled'                => 'no',
                'enable_google'          => 'no',
                'google_one_tap'         => 'no',
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
        }

        if ($settings['enable_google'] != 'yes') {
            $settings['google_key_method'] = 'wp_config';
            $settings['google_client_id'] = '';
            $settings['google_client_secret'] = '';
        } else if ($settings['google_key_method'] == 'wp_config') {
            $settings['google_client_id'] = '';
            $settings['google_client_secret'] = '';
            if (!defined('FLUENT_AUTH_GOOGLE_CLIENT_ID') || !defined('FLUENT_AUTH_GOOGLE_CLIENT_SECRET')) {
                return new \WP_Error('validation_error', 'Form Validation failed', [
                    'google_key_method' => [
                        'FLUENT_AUTH_GOOGLE_CLIENT_ID'     => 'FLUENT_AUTH_GOOGLE_CLIENT_ID constant is required in wp-config.php file',
                        'FLUENT_AUTH_GOOGLE_CLIENT_SECRET' => 'FLUENT_AUTH_GOOGLE_CLIENT_SECRET constant is required in wp-config.php file',
                    ]
                ]);
            }
        } else {
            $settings['google_client_id'] = sanitize_textarea_field($settings['google_client_id']);
            $settings['google_client_secret'] = sanitize_textarea_field($settings['google_client_secret']);
            if (empty($settings['google_client_id']) || empty($settings['google_client_secret'])) {
                return new \WP_Error('validation_error', 'Form Validation failed', [
                    'google_client_id'     => [
                        'required' => 'Google Client ID is required'
                    ],
                    'google_client_secret' => [
                        'required' => 'Google Client Secret is required'
                    ]
                ]);
            }
        }

        if ($settings['enable_github'] != 'yes') {
            $settings['github_key_method'] = 'wp_config';
            $settings['github_client_id'] = '';
            $settings['github_client_secret'] = '';
        } else if ($settings['github_key_method'] == 'wp_config') {
            $settings['github_client_id'] = '';
            $settings['github_client_secret'] = '';
            if (!defined('FLUENT_AUTH_GITHUB_CLIENT_ID') || !defined('FLUENT_AUTH_GITHUB_CLIENT_SECRET')) {
                return new \WP_Error('validation_error', 'Form Validation failed', [
                    'github_key_method' => [
                        'FLUENT_AUTH_GITHUB_CLIENT_ID'     => 'FLUENT_AUTH_GITHUB_CLIENT_ID constant is required in wp-config.php file',
                        'FLUENT_AUTH_GITHUB_CLIENT_SECRET' => 'FLUENT_AUTH_GITHUB_CLIENT_SECRET constant is required in wp-config.php file',
                    ]
                ]);
            }
        } else {
            $settings['github_client_id'] = sanitize_textarea_field($settings['github_client_id']);
            $settings['github_client_secret'] = sanitize_textarea_field($settings['github_client_secret']);
            if (empty($settings['github_client_id']) || empty($settings['github_client_secret'])) {
                return new \WP_Error('validation_error', 'Form Validation failed', [
                    'github_client_id'     => [
                        'required' => 'Github Client ID is required'
                    ],
                    'github_client_secret' => [
                        'required' => 'Github Client Secret is required'
                    ]
                ]);
            }
        }

        if ($settings['enable_facebook'] != 'yes') {
            $settings['facebook_key_method'] = 'wp_config';
            $settings['facebook_client_id'] = '';
            $settings['facebook_client_secret'] = '';
            $settings['facebook_api_version'] = 'v12.0';
        } else if ($settings['facebook_key_method'] == 'wp_config') {
            $settings['facebook_client_id'] = '';
            $settings['facebook_client_secret'] = '';
            if (!defined('FLUENT_AUTH_FACEBOOK_CLIENT_ID') || !defined('FLUENT_AUTH_FACEBOOK_CLIENT_SECRET')) {
                return new \WP_Error('validation_error', 'Form Validation failed', [
                    'facebook_key_method' => [
                        'FLUENT_AUTH_FACEBOOK_CLIENT_ID'     => 'FLUENT_AUTH_FACEBOOK_CLIENT_ID constant is required in wp-config.php file',
                        'FLUENT_AUTH_FACEBOOK_CLIENT_SECRET' => 'FLUENT_AUTH_FACEBOOK_CLIENT_SECRET constant is required in wp-config.php file',
                    ]
                ]);
            }
        } else {
            $settings['facebook_client_id'] = sanitize_textarea_field($settings['facebook_client_id']);
            $settings['facebook_client_secret'] = sanitize_textarea_field($settings['facebook_client_secret']);
            if (empty($settings['facebook_client_id']) || empty($settings['facebook_client_secret'])) {
                return new \WP_Error('validation_error', 'Form Validation failed', [
                    'facebook_client_id'     => [
                        'required' => 'Facebook Client ID is required'
                    ],
                    'facebook_client_secret' => [
                        'required' => 'Facebook Client Secret is required'
                    ]
                ]);
            }
        }

        return $settings;
    }
}
