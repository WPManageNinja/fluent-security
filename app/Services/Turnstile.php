<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;

/**
 * Cloudflare Turnstile on the forms a bot uses to make the site send email.
 *
 * Three places, each switched on by itself: the signup forms, the login and password
 * reset forms, and WooCommerce's My Account login and signup. Checkout is left alone on
 * purpose - a refusal there costs a sale.
 *
 * The keys are FluentAuth's own. Keys found in Fluent Forms or FluentCart are offered
 * on the settings screen, and taking them copies them here. A live link would leave this
 * depending on a plugin that can be deactivated or cleared without anybody looking here.
 */
class Turnstile
{
    const OPTION = '__fls_turnstile_settings';

    const SIGNUP = 'signup';
    const LOGIN = 'login';
    const WOO = 'woo';

    const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

    /**
     * The field Cloudflare's script adds to the form it renders in.
     */
    const RESPONSE_FIELD = 'cf-turnstile-response';

    /**
     * @return array
     */
    public static function getSettings()
    {
        $defaults = [
            'site_key'     => '',
            'secret_key'   => '',
            self::SIGNUP   => 'no',
            self::LOGIN    => 'no',
            self::WOO      => 'no'
        ];

        $settings = get_option(self::OPTION, []);

        if (!is_array($settings)) {
            $settings = [];
        }

        return array_merge($defaults, array_intersect_key($settings, $defaults));
    }

    /**
     * The way back in when the widget cannot run - the site moved to a domain the widget
     * does not list, or the widget was deleted in Cloudflare. The server cannot tell a
     * broken widget from a bot that sent no token, so it refuses both, and with login
     * guarded that includes the administrator. A constant because whoever is locked out
     * cannot reach a setting.
     *
     * @return bool
     */
    public static function isDisabledByConstant()
    {
        return defined('FLUENT_AUTH_DISABLE_TURNSTILE') && FLUENT_AUTH_DISABLE_TURNSTILE;
    }

    /**
     * Whether Turnstile guards this place right now. The WooCommerce place also needs
     * WooCommerce, so a setting left on after it is removed does nothing.
     *
     * @param string $place one of the SIGNUP, LOGIN or WOO constants
     * @return bool
     */
    public static function isActive($place)
    {
        if (self::isDisabledByConstant()) {
            return false;
        }

        $settings = self::getSettings();

        if (!$settings['site_key'] || !$settings['secret_key']) {
            return false;
        }

        if ($place === self::WOO && !class_exists('WooCommerce')) {
            return false;
        }

        return Arr::get($settings, $place) === 'yes';
    }

    /**
     * The widget for a form, with Cloudflare's script queued behind it. The script finds
     * the widget by its class and puts the token in a hidden field of the same form.
     *
     * @param string $place
     * @return string empty when this place is not guarded
     */
    public static function widget($place)
    {
        if (!self::isActive($place)) {
            return '';
        }

        self::enqueueScript();

        return '<div class="fls_turnstile cf-turnstile" data-sitekey="' . esc_attr(self::getSettings()['site_key']) . '" data-theme="auto" data-size="flexible" style="margin: 0 0 16px;"></div>';
    }

    /**
     * @return void
     */
    public static function enqueueScript()
    {
        // No version: a query string on Cloudflare's script is a copy it does not serve.
        wp_enqueue_script('fluent_auth_turnstile', self::SCRIPT_URL, [], null, [
            'in_footer' => true,
            'strategy'  => 'async'
        ]);
    }

    /**
     * Checks the token the current request carries, when this place is guarded.
     *
     * @param string $place
     * @return true|\WP_Error
     */
    public static function check($place)
    {
        if (!self::isActive($place)) {
            return true;
        }

        $token = Arr::get($_POST, self::RESPONSE_FIELD, '');

        return self::verify(is_string($token) ? sanitize_text_field(wp_unslash($token)) : '', self::getSettings()['secret_key']);
    }

    /**
     * Asks Cloudflare whether a token is good.
     *
     * Refuses only on Cloudflare's own word that the token is missing, bad or used. When
     * Cloudflare cannot be reached, or says the secret key is wrong, the form goes
     * through. Otherwise an outage or a key rotated in Cloudflare's dashboard would stop
     * every password login on the site, administrators included.
     *
     * @param string $token
     * @param string $secretKey
     * @return true|\WP_Error
     */
    public static function verify($token, $secretKey)
    {
        if (!$token) {
            return self::refusal();
        }

        $response = wp_remote_post(self::VERIFY_URL, [
            'timeout' => 10,
            'body'    => [
                'secret'   => $secretKey,
                'response' => $token
            ]
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 500) {
            return true;
        }

        /*
         * The body decides, never the status. Cloudflare answers a bad secret with a 400,
         * and a page from its edge, such as a 403, carries no answer about the token at all.
         */
        $result = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($result)) {
            return true;
        }

        if (!empty($result['success'])) {
            return true;
        }

        $codes = (array)Arr::get($result, 'error-codes', []);

        foreach ($codes as $code) {
            if (strpos((string)$code, 'secret') !== false || $code === 'internal-error') {
                return true;
            }
        }

        return self::refusal();
    }

    /**
     * Whether a pair of keys works, for the settings screen. Strict where verify() is
     * lenient: a wrong secret or no answer at all is exactly what the owner needs to see
     * before saving.
     *
     * @param string $token from the widget the settings screen rendered with the site key
     * @param string $secretKey
     * @return true|\WP_Error
     */
    public static function testKeys($token, $secretKey)
    {
        if (!$token) {
            return new \WP_Error('turnstile_no_token', __('Complete the Turnstile check on this screen first. If it does not appear, the site key is wrong or this domain is not added to the widget in Cloudflare.', 'fluent-security'), ['status' => 422]);
        }

        $response = wp_remote_post(self::VERIFY_URL, [
            'timeout' => 10,
            'body'    => [
                'secret'   => $secretKey,
                'response' => $token
            ]
        ]);

        if (is_wp_error($response)) {
            return new \WP_Error('turnstile_unreachable', __('Could not reach Cloudflare to check the keys. Please try again.', 'fluent-security'), ['status' => 422]);
        }

        $result = json_decode(wp_remote_retrieve_body($response), true);

        if (is_array($result) && !empty($result['success'])) {
            return true;
        }

        return new \WP_Error('turnstile_invalid_keys', __('Cloudflare did not accept these keys. Check that the secret key belongs to the same widget as the site key.', 'fluent-security'), ['status' => 422]);
    }

    /**
     * Turnstile keys saved by other Fluent plugins on this site, offered on the settings
     * screen so the owner does not have to fetch them from Cloudflare again.
     *
     * @return array
     */
    public static function getKeySources()
    {
        $sources = [];

        $fluentForms = get_option('_fluentform_turnstile_details');

        if (is_array($fluentForms) && !empty($fluentForms['siteKey']) && !empty($fluentForms['secretKey'])) {
            $sources[] = [
                'key'        => 'fluentform',
                'title'      => 'Fluent Forms',
                'site_key'   => (string)$fluentForms['siteKey'],
                'secret_key' => (string)$fluentForms['secretKey']
            ];
        }

        $fluentCart = Arr::get((array)get_option('fluent_cart_modules_settings', []), 'turnstile');

        if (is_array($fluentCart) && !empty($fluentCart['site_key']) && !empty($fluentCart['secret_key'])) {
            $sources[] = [
                'key'        => 'fluent-cart',
                'title'      => 'FluentCart',
                'site_key'   => (string)$fluentCart['site_key'],
                'secret_key' => (string)$fluentCart['secret_key']
            ];
        }

        return $sources;
    }

    /**
     * The signup forms anyone can use right now with nothing checking for bots, for the
     * dashboard to point at.
     *
     * @return array 'wordpress' and/or 'woocommerce'
     */
    public static function unguardedSignups()
    {
        $open = [];

        // Multisite signs people up on wp-signup.php, which has no widget to switch on.
        if (!is_multisite() && get_option('users_can_register') && !self::isActive(self::SIGNUP)) {
            $open[] = 'wordpress';
        }

        if (class_exists('WooCommerce') && get_option('woocommerce_enable_myaccount_registration') === 'yes' && !self::isActive(self::WOO)) {
            $open[] = 'woocommerce';
        }

        return $open;
    }

    /**
     * @return \WP_Error
     */
    private static function refusal()
    {
        return new \WP_Error('fls_turnstile_failed', __('Please complete the security check and try again.', 'fluent-security'));
    }
}
