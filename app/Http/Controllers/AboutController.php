<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\AboutPage;

class AboutController
{
    public static function index(\WP_REST_Request $request)
    {
        return [
            'plugins'      => AboutPage::plugins(),
            'can_install'  => AboutPage::canInstall(),
            'can_activate' => current_user_can('activate_plugins'),
            'version'      => FLUENT_AUTH_VERSION
        ];
    }

    public static function contributors(\WP_REST_Request $request)
    {
        return [
            'contributors' => AboutPage::contributors()
        ];
    }

    public static function installPlugin(\WP_REST_Request $request)
    {
        $plugin = AboutPage::installAndActivate(sanitize_key((string)$request->get_param('slug')));

        if (is_wp_error($plugin)) {
            return $plugin;
        }

        return [
            'plugin'  => $plugin,
            /* translators: %s: plugin name */
            'message' => sprintf(__('%s is installed and active.', 'fluent-security'), $plugin['name'])
        ];
    }
}
