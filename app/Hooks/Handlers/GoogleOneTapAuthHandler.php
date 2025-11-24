<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class GoogleOneTapAuthHandler
{

    public function register()
    {
        add_action('fluent_auth/init_google_popup_auth', [$this, 'initGooglePopupAuth']);
        //do_action('fluent_auth/init_google_popup_auth', []);

        add_action('login_enqueue_scripts', function () {
            $this->fluentAuthOneTabloadAssets([
                'type'  => 'inline',
                'delay' => 0
            ]);
        });

        add_shortcode('fluent_auth_google_one_tap', function ($atts) {
            if (!$this->isEnabled()) {
                return '';
            }

            if (is_user_logged_in()) {
                return '';
            }

            $atts = shortcode_atts([
                'type'  => 'inline',
                'delay' => 2
            ], $atts, 'fluent_auth_google_one_tap');

            $this->initGooglePopupAuth($atts);

            if ($atts['type'] === 'inline') {
                return '<div id="fluent-google-one-tap-button"></div>';
            }

            return '';
        });

    }

    public function initGooglePopupAuth($args = [])
    {

        if (is_user_logged_in()) {
            return '';
        }

        if (!$this->isEnabled()) {
            return '';
        }

        $defaults = [
            'type'  => 'global',
            'delay' => 2
        ];

        $args = wp_parse_args($args, $defaults);

        if (did_action('wp_enqueue_scripts')) {
            $this->fluentAuthOneTabloadAssets($args);
        } else {
            add_action('wp_enqueue_scripts', function () use ($args) {
                $this->fluentAuthOneTabloadAssets($args);
            });
        }

    }

    public function fluentAuthOneTabloadAssets($args = [])
    {
        $config = Helper::getSocialAuthSettings('edit');
        if ($config['enabled'] !== 'yes' || $config['enable_google'] != 'yes' || empty($config['google_client_id'])) {
            return;
        }

        wp_enqueue_script('google-one-tap-client-js', 'https://accounts.google.com/gsi/client', [], '', [
            'in_footer' => true
        ]);

        wp_enqueue_script('fluent-auth-google-one-tap', FLUENT_AUTH_PLUGIN_URL . 'dist/public/one_tap.js', ['google-one-tap-client-js'], FLUENT_AUTH_VERSION, [
            'in_footer' => true
        ]);

        wp_localize_script('fluent-auth-google-one-tap', 'fluentOneTapConfig', [
            'type'      => $args['type'],
            'delay'     => intval($args['delay']),
            'client_id' => $config['google_client_id'],
            'ajax_url'  => admin_url('admin-ajax.php')
        ]);
    }

    private function isEnabled($config = null)
    {
        if (!$config) {
            $config = Helper::getSocialAuthSettings('edit');
        }

        if ($config['enabled'] !== 'yes' || $config['enable_google'] != 'yes' || empty($config['google_client_id'])) {
            return;
        }

        return true;

    }

}
