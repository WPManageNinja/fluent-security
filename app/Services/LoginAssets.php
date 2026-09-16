<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Helper;

/**
 * The one script the login screens run, and the one object it reads.
 *
 * Everything the browser does on a login screen - the shortcode forms, the second
 * factor challenge, all three WebAuthn ceremonies and the magic link - used to be
 * spread across two bundles and three inline <script> blocks, each enqueued by
 * whichever handler happened to render the markup. That made the order they ran in a
 * function of which <script> tag the parser reached first, which is how the passkey
 * button and the magic link came to need a setTimeout to agree on who draws the
 * separator between them.
 *
 * One file, enqueued once, settles that by construction: the order is the order the
 * functions are called in. Whoever renders first asks for the assets, everyone after
 * gets the same handle back, and the config is built in full here rather than a piece
 * at a time by each caller.
 *
 * Google One Tap stays out of it on purpose - it depends on a script served from
 * accounts.google.com, and folding it in would put that request on every login page
 * instead of the ones that asked for it.
 */
class LoginAssets
{
    /**
     * @var bool whether the script has already gone out in this request
     */
    private static $enqueued = false;

    /**
     * @return void
     */
    public static function enqueue()
    {
        if (self::$enqueued) {
            return;
        }

        self::$enqueued = true;

        /*
         * Enqueued rather than injected from the bundle, and enqueued before the script so
         * it is in the queue behind core's own login.css. That order is the whole point:
         * `.login * { margin: 0; padding: 0 }` ties with any single-class rule of ours, so
         * whichever of the two the browser reads last wins, and a stylesheet style-loader
         * appends while the script runs is read first.
         */
        wp_enqueue_style(
            'fluent_auth_login_helper',
            FLUENT_AUTH_PLUGIN_URL . 'dist/public/login_helper.css',
            [],
            FLUENT_AUTH_VERSION
        );

        wp_enqueue_script(
            'fluent_auth_login_helper',
            FLUENT_AUTH_PLUGIN_URL . 'dist/public/login_helper.js',
            [],
            FLUENT_AUTH_VERSION
        );

        wp_localize_script('fluent_auth_login_helper', 'fluentAuthPublic', self::getConfig());
    }

    /**
     * @return void
     */
    public static function reset()
    {
        self::$enqueued = false;
    }

    /**
     * @return array
     */
    private static function getConfig()
    {
        $config = [
            'ajax_url'          => admin_url('admin-ajax.php'),
            'redirect_fallback' => site_url(),
            'fls_login_nonce'   => wp_create_nonce('fsecurity_login_nonce'),
            'i18n'              => [
                'Username_or_Email' => __('Username or Email', 'fluent-security'),
                'Password'          => __('Password', 'fluent-security'),
                'network_error'     => __('Could not reach the site. Check your connection and try again.', 'fluent-security')
            ]
        ];

        /*
         * Absent rather than empty when magic login is off, because that absence is what
         * the script tests before it touches the magic form at all.
         */
        if (Helper::getSetting('magic_login') === 'yes') {
            $config['magic'] = [
                'success_icon' => FLUENT_AUTH_PLUGIN_URL . 'dist/images/success.png',
                'empty_text'   => __('Please provide username / email to get magic login link', 'fluent-security'),
                'wait_text'    => __('Please Wait...', 'fluent-security'),
                'is_primary'   => Helper::getSetting('magic_link_primary') === 'yes'
            ];
        }

        return apply_filters('fluent_auth/login_assets_config', $config);
    }
}
