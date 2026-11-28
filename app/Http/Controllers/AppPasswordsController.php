<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AppPasswords;

class AppPasswordsController
{
    public static function index(\WP_REST_Request $request)
    {
        return self::payload();
    }

    public static function revoke(\WP_REST_Request $request)
    {
        $result = AppPasswords::revoke((int)$request->get_param('user_id'), (string)$request->get_param('uuid'));

        if (is_wp_error($result)) {
            return $result;
        }

        return self::payload() + [
            'message' => __('The application password has been revoked. Anything using it can no longer sign in.', 'fluent-security')
        ];
    }

    public static function revokeUnused(\WP_REST_Request $request)
    {
        $count = AppPasswords::revokeUnused();

        return self::payload() + [
            /* translators: %d: how many application passwords were revoked */
            'message' => sprintf(_n('%d unused application password has been revoked.', '%d unused application passwords have been revoked.', $count, 'fluent-security'), $count)
        ];
    }

    private static function payload()
    {
        return [
            'passwords'   => AppPasswords::all(),
            'unused_days' => AppPasswords::UNUSED_DAYS,
            /* Off by the plugin's own setting, or by core / another plugin: either way none of these can sign in. */
            'available'   => function_exists('wp_is_application_passwords_available') && wp_is_application_passwords_available(),
            'turned_off_here' => Helper::getSetting('disable_app_login') === 'yes'
        ];
    }
}
