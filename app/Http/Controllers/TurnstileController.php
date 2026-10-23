<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\Turnstile;

class TurnstileController
{
    public static function getSettings(\WP_REST_Request $request)
    {
        return [
            'settings' => Turnstile::getSettings(),
            'sources'  => Turnstile::getKeySources(),
            'has_woo'  => class_exists('WooCommerce'),
            'disabled_by_constant' => Turnstile::isDisabledByConstant(),
            // What the owner adds under Hostnames in Cloudflare. Two when wp-admin lives elsewhere.
            'hostnames' => array_values(array_unique(array_filter([
                wp_parse_url(home_url(), PHP_URL_HOST),
                wp_parse_url(site_url(), PHP_URL_HOST)
            ])))
        ];
    }

    /**
     * New keys are saved only with a token from the widget the screen rendered with the
     * new site key. That proves the site key works on this domain and the secret key
     * belongs to it, which is the mistake that would otherwise surface as a login form
     * nobody can get through.
     *
     * @param \WP_REST_Request $request
     * @return array|\WP_Error
     */
    public static function saveSettings(\WP_REST_Request $request)
    {
        $input = (array)$request->get_param('settings');

        $settings = [
            'site_key'   => trim(sanitize_text_field((string)Arr::get($input, 'site_key', ''))),
            'secret_key' => trim(sanitize_text_field((string)Arr::get($input, 'secret_key', '')))
        ];

        foreach ([Turnstile::SIGNUP, Turnstile::LOGIN, Turnstile::WOO] as $place) {
            $settings[$place] = Arr::get($input, $place) === 'yes' ? 'yes' : 'no';
        }

        if (!$settings['site_key'] xor !$settings['secret_key']) {
            return new \WP_Error('turnstile_missing_key', __('Enter both the site key and the secret key.', 'fluent-security'), ['status' => 422]);
        }

        $stored = Turnstile::getSettings();

        $keysChanged = $settings['site_key'] !== $stored['site_key'] || $settings['secret_key'] !== $stored['secret_key'];

        if ($keysChanged && $settings['site_key']) {
            $tested = Turnstile::testKeys(sanitize_text_field((string)$request->get_param('token')), $settings['secret_key']);

            if (is_wp_error($tested)) {
                return $tested;
            }
        }

        update_option(Turnstile::OPTION, $settings, true);

        return [
            'settings' => Turnstile::getSettings(),
            'message'  => __('Bot protection settings have been saved.', 'fluent-security')
        ];
    }
}
