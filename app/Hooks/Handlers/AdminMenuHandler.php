<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TransStrings;

class AdminMenuHandler
{
    public function register()
    {
        add_action('admin_menu', array($this, 'addMenu'));
    }

    public function addMenu()
    {
        $permission = Helper::getAppPermission();
        if (!$permission) {
            return;
        }

        add_menu_page(
            __('FluentAuth Settings', 'fluent-security'),
            __('FluentAuth', 'fluent-security'),
            $permission,
            'fluent-auth',
            array($this, 'render'),
            $this->getMenuIcon(),
            120
        );

        add_submenu_page(
            'fluent-auth',
            __('Dashboard', 'fluent-security'),
            __('Dashboard', 'fluent-security'),
            $permission,
            'fluent-auth',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Logs', 'fluent-security'),
            __('Logs', 'fluent-security'),
            $permission,
            'fluent-auth#/logs',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Security Settings', 'fluent-security'),
            __('Security Settings', 'fluent-security'),
            $permission,
            'fluent-auth#/settings',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Login/Signup Forms', 'fluent-security'),
            __('Login/Signup Forms', 'fluent-security'),
            $permission,
            'fluent-auth#/auth-shortcodes',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Login Redirects', 'fluent-security'),
            __('Login Redirects', 'fluent-security'),
            $permission,
            'fluent-auth#/login-redirects',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Customize WP Emails', 'fluent-security'),
            __('Customize WP Emails', 'fluent-security'),
            $permission,
            'fluent-auth#/custom-wp-emails',
            array($this, 'render')
        );

        add_submenu_page(
            'fluent-auth',
            __('Security Scans', 'fluent-security'),
            __('Security Scans', 'fluent-security'),
            $permission,
            'fluent-auth#/security-scans',
            array($this, 'render')
        );
    }

    public function render()
    {
        if (!wp_next_scheduled('fluent_auth_daily_tasks')) {
            wp_schedule_event(time(), 'daily', 'fluent_auth_daily_tasks');
        }

        if (!wp_next_scheduled('fluent_auth_hourly_tasks')) {
            wp_schedule_event(time(), 'hourly', 'fluent_auth_hourly_tasks');
        }

        add_filter('admin_footer_text', function ($content) {
            return 'Thank you for using <a rel="noopener"  target="_blank" href="https://fluentauth.com">FluentAuth</a> | Write a <a target="_blank" rel="noopener" href="https://wordpress.org/support/plugin/fluent-security/reviews/?filter=5">review for FluentAuth</a>';
        });

        $currentUser = wp_get_current_user();

        if (function_exists('wp_enqueue_media')) {
            // Editor default styles.
            add_filter('user_can_richedit', '__return_true');
            wp_tinymce_inline_scripts();
            wp_enqueue_editor();
            wp_enqueue_media();
        }

        wp_enqueue_script('diff', FLUENT_AUTH_PLUGIN_URL . 'dist/libs/diff.js', [], '7.0.0', true);

        wp_enqueue_script('fluent_auth_app', FLUENT_AUTH_PLUGIN_URL . 'dist/admin/app.js', ['jquery'], FLUENT_AUTH_VERSION, true);

        $fullName = trim($currentUser->first_name . ' ' . $currentUser->last_name);

        if (!$fullName) {
            $fullName = $currentUser->display_name;
        }

        wp_localize_script('fluent_auth_app', 'fluentAuthAdmin', apply_filters('fluent_security/app_vars', [
            'slug'            => 'fluent-security',
            'nonce'           => wp_create_nonce('fluent-security'),
            'rest'            => [
                'base_url'  => esc_url_raw(rest_url()),
                'url'       => rest_url('fluent-auth'),
                'nonce'     => wp_create_nonce('wp_rest'),
                'namespace' => 'fluent-auth',
                'version'   => '1'
            ],
            'auth_statuses'   => [
                'failed'  => __('Failed', 'fluent-security'),
                'blocked' => __('Blocked', 'fluent-security'),
                'success' => __('Successful', 'fluent-security')
            ],
            'auth_settings'   => Helper::getAuthSettings(),
            'asset_url'       => FLUENT_AUTH_PLUGIN_URL . 'dist/',
            'me'              => [
                'id'        => $currentUser->ID,
                'full_name' => $fullName,
                'email'     => $currentUser->user_email
            ],
            'is_onboarding'   => true,
            'i18n'            => TransStrings::getStrings(),
            'suggestedColors' => ['#000000', '#abb8c3', '#ffffff', '#f78da7', '#ff6900', '#fcb900', '#7bdcb5', '#00d084', '#8ed1fc', '#0693e3', '#9b51e0']
        ]));

        echo '<div id="fluent_auth_app"><h3 style="text-align: center; margin-top: 100px;">Loading Settings..</h3></div>';
    }

    private function getMenuIcon()
    {
        return 'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 182.8 203.1"><defs><style>.cls-1{fill:#fff;}</style></defs><g id="Layer_2" data-name="Layer 2"><g id="Layer_1-2" data-name="Layer 1"><path class="cls-1" d="M182.75,23.08S171.7,19.83,140.16,11.7C106.78,3.1,91.4,0,91.4,0S76,3.1,42.64,11.7C11.11,19.83.06,23.08.06,23.08s-1.63,32.5,12.68,91.34c11.54,47.5,54.61,73.79,78.66,88.68,24.06-14.89,67.12-41.18,78.67-88.68C184.37,55.58,182.75,23.08,182.75,23.08ZM90.89,125.68,39.63,139.41V128a17,17,0,0,1,12.58-16.39l62.3-16.71A31.9,31.9,0,0,1,90.89,125.68Zm46.66-50.45L39.63,101.46V90a17,17,0,0,1,12.58-16.4l109-29.2A31.94,31.94,0,0,1,137.55,75.23Z"/></g></g></svg>');
    }
}
