<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\GoogleAuthService;

class GoogleOneTapAuthHandler
{

    public function register()
    {
        add_action('fluent_auth/init_google_popup_auth', [$this, 'initGooglePopupAuth']);

        add_action('fluent_auth/social/rendering_button_google', function () {
            if (!$this->isOnetapEnabled()) {
                return;
            }
            $this->initGooglePopupAuth([
                'type'  => 'inline',
                'delay' => 0
            ]);
        });

        add_filter('fluent_auth/is_google_one_tap_enabled', function () {
            return $this->isOnetapEnabled();
        });

        add_action('login_enqueue_scripts', function () {
            if (!$this->isOnetapEnabled()) {
                return;
            }

            $this->fluentAuthOneTabloadAssets([
                'type'  => 'inline',
                'delay' => 0
            ]);
        });

        add_shortcode('fluent_auth_google_one_tap', function ($atts) {
            if (!$this->isOnetapEnabled() || is_user_logged_in()) {
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

        add_action('wp_ajax_fluent_security_google_one_tap_login', [$this, 'handleGoogleOneTapLogin']);
        add_action('wp_ajax_nopriv_fluent_security_google_one_tap_login', [$this, 'handleGoogleOneTapLogin']);
    }

    public function handleGoogleOneTapLogin()
    {
        if (is_user_logged_in()) {
            $redirectUrl = admin_url();
            if ($_POST['mode'] !== 'inline') {
                $providedUrl = isset($_POST['current_url']) ? $_POST['current_url'] : '';
                if (filter_var($providedUrl, FILTER_VALIDATE_URL)) {
                    $redirectUrl = esc_url_raw($providedUrl);
                }
            }

            wp_send_json([
                'message'      => __('You are already logged in.', 'fluent-security'),
                'redirect_url' => $redirectUrl
            ]);
        }

        $crednetial = isset($_POST['credential']) ? sanitize_text_field($_POST['credential']) : '';

        $redirectUrl = $this->handleGoogleTokenConfirm($crednetial);

        if (is_wp_error($redirectUrl)) {
            wp_send_json([
                'message' => $redirectUrl->get_error_message()
            ], 422);
        }

        if (is_user_logged_in() && $_POST['mode'] !== 'inline') {
            $providedUrl = isset($_POST['current_url']) ? $_POST['current_url'] : '';
            if (filter_var($providedUrl, FILTER_VALIDATE_URL)) {
                $redirectUrl = esc_url_raw($providedUrl);
            }
        }

        wp_send_json([
            'redirect_url' => $redirectUrl
        ]);
    }

    private function handleGoogleTokenConfirm($crednetial)
    {
        $tokenData = \FluentAuth\App\Services\GoogleAuthService::verifyClientToken($crednetial);

        if (is_wp_error($tokenData)) {
            return $tokenData;
        }

        $username = Arr::get($tokenData, 'email');
        $emailArray = explode('@', $username);
        if (count($emailArray)) {
            $username = $emailArray[0];
        }

        $userData = [
            'full_name' => Arr::get($tokenData, 'name'),
            'email'     => Arr::get($tokenData, 'email'),
            'username'  => $username,
            'photo'     => Arr::get($tokenData, 'picture')
        ];

        if (is_user_logged_in()) {
            $existingUser = get_user_by('ID', get_current_user_id());
            if ($existingUser->user_email !== $userData['email']) {
                return new \WP_Error('email_mismatch', __('Your Google email address does not match with your current account email address. Please use the same email address', 'fluent-security'));
            }
        }

        if (empty($userData['email']) || !is_email($userData['email'])) {
            return new \WP_Error('email_error', __('Sorry! we could not find your valid email from Google API', 'fluent-security'));
        }

        $existingUser = get_user_by('email', $userData['email']);
        if ($existingUser) {
            $twoFaHandler = new TwoFaHandler();
            if ($redirectUrl = $twoFaHandler->sendAndGet2FaConfirmFormUrl($existingUser)) {
                return $redirectUrl;
            }
        }

        $user = AuthService::doUserAuth($userData, 'google');

        if (is_wp_error($user)) {
            return $user;
        }

        $intentRedirectTo = '';
        if (isset($_COOKIE['fs_intent_redirect'])) {
            $cookieRedirect = $_COOKIE['fs_intent_redirect'];
            if (!filter_var($cookieRedirect, FILTER_VALIDATE_URL)) {
                $cookieRedirect = admin_url();
                $intentRedirectTo = '';
            }
            $redirect_to = $cookieRedirect;
        } else {
            if (is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin($user->ID)) {
                $redirect_to = user_admin_url();
            } elseif (is_multisite() && !$user->has_cap('read')) {
                $redirect_to = get_dashboard_url($user->ID);
            } elseif (!$user->has_cap('edit_posts')) {
                $redirect_to = $user->has_cap('read') ? admin_url('profile.php') : home_url();
            } else {
                $redirect_to = admin_url();
            }
        }

        update_user_meta($user->ID, '_fls_login_google', $userData['email']);

        return apply_filters('login_redirect', $redirect_to, $intentRedirectTo, $user);
    }

    public function initGooglePopupAuth($args = [])
    {
        if (is_user_logged_in() || !$this->isOnetapEnabled()) {
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

        return (new SocialAuthHandler())->isEnabled('google');


    }

    private function isOnetapEnabled($config = null)
    {
        if (!$this->isEnabled()) {
            return false;
        }

        if (!$config) {
            $config = Helper::getSocialAuthSettings('edit');
        }

        return Arr::get($config, 'google_one_tap') === 'yes';
    }

}
