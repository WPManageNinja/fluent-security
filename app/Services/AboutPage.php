<?php

namespace FluentAuth\App\Services;

/**
 * The About screen: a few of the team's other plugins, installable in one click, and the
 * people who build FluentAuth.
 *
 * Only plugins on the list below can be installed from here, only from WordPress.org, and
 * only by someone WordPress already lets install plugins. Nothing is installed or fetched
 * until the admin clicks.
 */
class AboutPage
{
    const CONTRIBUTORS_CACHE = 'fls_github_contributors';

    /**
     * @return array[] slug => [file, name, admin page]. The order is the order on screen.
     */
    private static function catalogue()
    {
        return [
            'fluent-smtp'      => ['fluent-smtp/fluent-smtp.php', 'FluentSMTP', 'options-general.php?page=fluent-mail', 'svg'],
            'fluent-crm'       => ['fluent-crm/fluent-crm.php', 'FluentCRM', 'admin.php?page=fluentcrm-admin', 'svg'],
            'fluent-cart'      => ['fluent-cart/fluent-cart.php', 'FluentCart', 'admin.php?page=fluent-cart', 'svg'],
            'fluentform'       => ['fluentform/fluentform.php', 'Fluent Forms', 'admin.php?page=fluent_forms', 'png'],
            'fluent-community' => ['fluent-community/fluent-community.php', 'FluentCommunity', 'admin.php?page=fluent-community', 'svg'],
            'fluent-booking'   => ['fluent-booking/fluent-booking.php', 'FluentBooking', 'admin.php?page=fluent-booking', 'svg'],
            'fluent-support'   => ['fluent-support/fluent-support.php', 'Fluent Support', 'admin.php?page=fluent-support', 'svg'],
        ];
    }

    private static function pitch($slug)
    {
        $pitches = [
            'fluent-smtp'      => __('Two-factor codes, magic links and password resets are all emails. FluentSMTP makes sure they arrive, so nobody gets locked out.', 'fluent-security'),
            'fluent-crm'       => __('Email marketing and automation inside WordPress. Your contacts stay on your site.', 'fluent-security'),
            'fluent-cart'      => __('A fast store and checkout. FluentAuth already protects its customer logins.', 'fluent-security'),
            'fluentform'       => __('The form builder used on more than 800,000 sites. Contact forms, surveys, quizzes and payments.', 'fluent-security'),
            'fluent-community' => __('A community and courses on your own site. Its sign-in screens run on FluentAuth.', 'fluent-security'),
            'fluent-booking'   => __('Appointments and event booking with calendar sync.', 'fluent-security'),
            'fluent-support'   => __('A helpdesk and ticket system that lives in your WordPress admin.', 'fluent-security'),
        ];

        return $pitches[$slug] ?? '';
    }

    /**
     * @return array[] each plugin with its state on this site: active, installed, or not.
     */
    public static function plugins()
    {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $installed = get_plugins();
        $rows = [];

        foreach (self::catalogue() as $slug => [$file, $name, $adminPage, $iconExt]) {
            $state = 'missing';
            if (isset($installed[$file])) {
                $state = is_plugin_active($file) ? 'active' : 'installed';
            }

            $rows[] = [
                'slug'      => $slug,
                'name'      => $name,
                'pitch'     => self::pitch($slug),
                'icon'      => FLUENT_AUTH_PLUGIN_URL . 'dist/images/plugins/' . $slug . '.' . $iconExt,
                'state'     => $state,
                'admin_url' => admin_url($adminPage),
                'info_url'  => 'https://wordpress.org/plugins/' . $slug . '/'
            ];
        }

        return $rows;
    }

    /** Whether this admin may install plugins here, the way WordPress's own screen decides. */
    public static function canInstall()
    {
        return current_user_can('install_plugins') && wp_is_file_mod_allowed('install_plugins');
    }

    /**
     * Installs the plugin from WordPress.org if it is missing, then activates it.
     *
     * @return array|\WP_Error the plugin's updated row
     */
    public static function installAndActivate($slug)
    {
        $catalogue = self::catalogue();

        if (!isset($catalogue[$slug])) {
            return new \WP_Error('unknown_plugin', __('That plugin cannot be installed from here.', 'fluent-security'), ['status' => 400]);
        }

        if (!current_user_can('activate_plugins')) {
            return new \WP_Error('forbidden', __('You are not allowed to activate plugins.', 'fluent-security'), ['status' => 403]);
        }

        $file = $catalogue[$slug][0];

        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        if (!isset(get_plugins()[$file])) {
            if (!self::canInstall()) {
                return new \WP_Error('forbidden', __('You are not allowed to install plugins on this site.', 'fluent-security'), ['status' => 403]);
            }

            $installed = self::install($slug);

            if (is_wp_error($installed)) {
                return $installed;
            }
        }

        if (!is_plugin_active($file)) {
            $activated = activate_plugin($file);

            if (is_wp_error($activated)) {
                return $activated;
            }
        }

        foreach (self::plugins() as $row) {
            if ($row['slug'] === $slug) {
                return $row;
            }
        }

        return new \WP_Error('install_failed', __('The plugin could not be installed.', 'fluent-security'), ['status' => 500]);
    }

    private static function install($slug)
    {
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

        $api = plugins_api('plugin_information', ['slug' => $slug, 'fields' => ['sections' => false]]);

        if (is_wp_error($api)) {
            return $api;
        }

        $downloadLink = is_object($api) ? ($api->download_link ?? '') : '';

        if (!$downloadLink) {
            return new \WP_Error('install_failed', __('WordPress.org did not return a download for this plugin.', 'fluent-security'), ['status' => 502]);
        }

        // The skin WordPress's own one-click installs use: it collects errors instead of printing.
        $skin = new \WP_Ajax_Upgrader_Skin();
        $result = (new \Plugin_Upgrader($skin))->install($downloadLink);

        if (is_wp_error($result)) {
            return $result;
        }

        if (is_wp_error($skin->result)) {
            return $skin->result;
        }

        if ($skin->get_errors()->has_errors()) {
            return $skin->get_errors();
        }

        if (!$result) {
            // Usually filesystem credentials: WordPress cannot write to the plugins folder.
            return new \WP_Error('install_failed', __('WordPress could not write the plugin to this site. Install it from Plugins → Add New instead.', 'fluent-security'), ['status' => 500]);
        }

        return true;
    }

    /**
     * The people who have contributed to FluentAuth on GitHub, cached for a day.
     *
     * @return array[] login, avatar and profile link; empty when GitHub could not be reached.
     */
    public static function contributors()
    {
        $cached = get_transient(self::CONTRIBUTORS_CACHE);

        if (is_array($cached)) {
            return $cached;
        }

        $response = wp_remote_get('https://api.github.com/repos/WPManageNinja/fluent-security/contributors?per_page=50', [
            'timeout'    => 5,
            // WordPress's default user agent carries the site's address; GitHub has no need of it.
            'user-agent' => 'FluentAuth',
            'headers'    => ['Accept' => 'application/vnd.github+json']
        ]);

        $people = [];

        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $data = json_decode(wp_remote_retrieve_body($response), true);

            foreach ((array)$data as $person) {
                if (!is_array($person) || ($person['type'] ?? '') !== 'User' || empty($person['login'])) {
                    continue;
                }

                $people[] = [
                    'login'  => sanitize_text_field($person['login']),
                    'avatar' => esc_url_raw(add_query_arg('s', 96, (string)($person['avatar_url'] ?? ''))),
                    'url'    => esc_url_raw((string)($person['html_url'] ?? ''))
                ];
            }
        }

        // A failed call is retried in an hour rather than on every visit.
        set_transient(self::CONTRIBUTORS_CACHE, $people, $people ? DAY_IN_SECONDS : HOUR_IN_SECONDS);

        return $people;
    }
}
