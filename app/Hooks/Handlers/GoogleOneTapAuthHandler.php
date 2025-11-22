<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class GoogleOneTapAuthHandler
{

    public function register()
    {
        add_action('fluent_auth/init_google_popup_auth', [$this, 'initGooglePopupAuth']);
        //do_action('fluent_auth/init_google_popup_auth', []);

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
                return '<div class="g_id_signin"></div>';
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

        $dataConfig = [
            'client_id' => $config['google_client_id'],
            'callback'  => 'handleFluentGAuthOneTapResponse'
        ];

        $initScript = '';

        if ($args['type'] === 'global') {
            $initScript = "
            function initFluentAuthOneTap() {
                google.accounts.id.initialize(" . wp_json_encode($dataConfig) . ");
                google.accounts.id.prompt();
            }; 
            document.addEventListener('DOMContentLoaded', function() {
                setTimeout(function() {
                    initFluentAuthOneTap();
                }, 2 * 1000);
            });";
        }

        wp_add_inline_script('google-one-tap-client-js', "function handleFluentGAuthOneTapResponse(response) {
                console.log(response);
            } " . $initScript, 'after'
        );

        if ($initScript) {
            return;
        }

        add_action('wp_footer', function () use ($config) {
            ?>
            <!-- g_id_onload contains Google Identity Services settings -->
            <div
                id="g_id_onload"
                data-auto_prompt="false"
                data-callback="handleFluentGAuthOneTapResponse"
                data-client_id="<?php echo esc_attr($config['google_client_id']); ?>"
            ></div>
            <?php
        }, 9999);
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
