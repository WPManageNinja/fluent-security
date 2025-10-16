<?php
defined('ABSPATH') or die;

/*
Plugin Name:  FluentAuth - Auth Security Plugin
Plugin URI:   https://fluentauth.com
Description:  Super Simple Login / Signup Security and Social Login Plugin for WordPress
Version:      2.0.3
Author:       Fluent Auth Team
Author URI:   https://fluentauth.com
License:      GPLv2 or later
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
Text Domain:  fluent-security
Domain Path:  /language/
*/


if (defined('FLUENT_AUTH_VERSION')) {
    return;
}

define('FLUENT_AUTH_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('FLUENT_AUTH_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FLUENT_AUTH_VERSION', '2.0.3');

class FluentAuthPlugin
{
    public function init()
    {
        $this->autoLoad();

        register_activation_hook(__FILE__, [$this, 'activatePlugin']);
        register_deactivation_hook(__FILE__, [$this, 'deactivatePlugin']);

        load_plugin_textdomain('fluent-security', false, dirname(plugin_basename(__FILE__)) . '/language');

        $plugin_file = plugin_basename(__FILE__);
        add_filter("plugin_action_links_{$plugin_file}", [$this, 'addContextLinks'], 10, 1);
    }

    public function activatePlugin($siteWide = false)
    {
        \FluentAuth\App\Helpers\Activator::activate($siteWide);
    }

    public function deactivatePlugin()
    {
        wp_clear_scheduled_hook('fluent_auth_daily_tasks');
        wp_clear_scheduled_hook('fluent_auth_hourly_tasks');
    }

    private function autoLoad()
    {
        spl_autoload_register(function ($class) {
            $match = 'FluentAuth';

            if (!preg_match("/\b{$match}\b/", $class)) {
                return;
            }

            $path = plugin_dir_path(__FILE__);

            $file = str_replace(
                ['FluentAuth', '\\', '/App/'],
                ['', DIRECTORY_SEPARATOR, 'app/'],
                $class
            );

            require(trailingslashit($path) . trim($file, '/') . '.php');
        });

        require_once FLUENT_AUTH_PLUGIN_PATH . 'app/Services/DB/wpfluent.php';

        add_action('rest_api_init', function () {
            require_once FLUENT_AUTH_PLUGIN_PATH . 'app/Http/routes.php';
        });

        require_once FLUENT_AUTH_PLUGIN_PATH . 'app/Hooks/hooks.php';
    }

    public function addContextLinks($actions)
    {
        $actions['settings'] = sprintf(
            '<a href="%s">%s</a>',
            esc_url(admin_url('admin.php?page=fluent-auth#/settings')),
            esc_html__('Settings', 'fluent-security')
        );

        $actions['dashboard_page'] = sprintf(
            '<a href="%s">%s</a>',
            esc_url(admin_url('admin.php?page=fluent-auth#/')),
            esc_html__('Dashboard', 'fluent-security')
        );

        return $actions;
    }
}

(new FluentAuthPlugin())->init();
