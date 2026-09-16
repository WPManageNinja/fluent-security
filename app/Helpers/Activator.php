<?php

namespace FluentAuth\App\Helpers;

class Activator
{
    public static function activate($network_wide)
    {
        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );

        global $wpdb;
        if ($network_wide) {
            // Retrieve all site IDs from this network (WordPress >= 4.6 provides easy to use functions for that).
            if (function_exists('get_sites') && function_exists('get_current_network_id')) {
                $site_ids = get_sites(array('fields' => 'ids', 'network_id' => get_current_network_id()));
            } else {
                $site_ids = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs WHERE site_id = $wpdb->siteid;");
            }
            // Install the plugin for all these sites.
            foreach ($site_ids as $site_id) {
                switch_to_blog($site_id);
                self::migrate();
                restore_current_blog();
            }
        } else {
            self::migrate();
        }
    }

    /**
     * Runs on activation only, which is all it has to do.
     *
     * Activation does not fire when a site updates the plugin, so anything here reaches
     * new installs and no one else. That is not a gap to work around - it is why no table
     * this plugin has added since creates itself here. A table that has to appear on a
     * site that already has the plugin makes itself on first use instead, where being
     * missing is the only state it has to handle: see FactorStore::ensureTable().
     *
     * So this is for the two tables that predate that pattern, on a site that has just
     * switched the plugin on for the first time.
     *
     * @return void
     */
    /**
     * Brings an existing site's settings forward, once.
     *
     * Separate from migrate(), which activation alone reaches - so anything put there
     * lands on new installs and on nobody who updated. This runs on `admin_init` behind
     * its own flag, and it deliberately touches nothing but the options row: no tables,
     * no schedules, nothing that would be expensive to run on a site that has just
     * updated and is being browsed.
     *
     * @return void
     */
    public static function maybeMigrateSettings()
    {
        if (get_option('__fls_required_roles_migrated')) {
            return;
        }

        self::migrateRequiredRoles();

        // Autoloaded: this is read on every request, and a non-autoloaded flag would be
        // a query on each one for the entire life of the install.
        update_option('__fls_required_roles_migrated', 'yes', true);
    }

    /**
     * Keeps a required-roles list meaning exactly what it meant before.
     *
     * The requirement used to be inert unless the same role also appeared in
     * `totp_2fa_roles` with `totp_2fa` switched on - a role named in one list and not the
     * other was a policy that silently did nothing. That is now fixed: requiring a factor
     * grants the methods that satisfy it, so those roles would start being enforced.
     *
     * Which is what the site owner asked for, but not today and without warning: the
     * first they would know is being held at the login screen on a morning they did not
     * plan for it. So the list is narrowed once, to what was actually in force, and the
     * new meaning applies to anything they save from here on.
     *
     * @return void
     */
    private static function migrateRequiredRoles()
    {
        $settings = get_option('__fls_auth_settings');

        if (!is_array($settings) || empty($settings['totp_required_roles'])) {
            return;
        }

        $required = array_values((array)$settings['totp_required_roles']);

        $enforceable = [];

        if (isset($settings['totp_2fa']) && $settings['totp_2fa'] === 'yes') {
            $allowed = isset($settings['totp_2fa_roles']) ? (array)$settings['totp_2fa_roles'] : [];
            $enforceable = array_values(array_intersect($required, $allowed));
        }

        if ($enforceable === $required) {
            return;
        }

        $settings['totp_required_roles'] = $enforceable;

        update_option('__fls_auth_settings', $settings);
    }

    private static function migrate()
    {
        self::migrateLogsTable();
        self::migrateHashesTable();

        if (!wp_next_scheduled('fluent_auth_daily_tasks')) {
            wp_schedule_event(time(), 'daily', 'fluent_auth_daily_tasks');
        }

        if (!wp_next_scheduled('fluent_auth_hourly_tasks')) {
            wp_schedule_event(time(), 'hourly', 'fluent_auth_hourly_tasks');
        }
    }

    private static function migrateLogsTable()
    {
        global $wpdb;
        $charsetCollate = $wpdb->get_charset_collate();
        $table = $wpdb->prefix . 'fls_auth_logs';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table'") != $table) {
            $sql = "CREATE TABLE $table (
                `id` BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
                `username` VARCHAR(192) NOT NULL,
                `user_id` BIGINT UNSIGNED NULL,
                `count` INT UNSIGNED NULL DEFAULT 1,
                `agent` VARCHAR(192) NULL,
                `browser` varchar(50) NULL,
                `device_os` varchar(50) NULL,
                `ip`    varchar(50) NULL,
                `status` varchar(50) NULL,
                `error_code` varchar(50) NULL DEFAULT '',
                `media` varchar(50) NULL DEFAULT 'web',
                `description` TINYTEXT NULL,
                `created_at` TIMESTAMP NULL,
                `updated_at` TIMESTAMP NULL,
                  KEY `created_at` (`created_at`),
                  KEY `ip` (`ip`(50)),
                  KEY `status` (`status`(50)),
                  KEY `media` (`media`(50)),
                  KEY `user_id` (`user_id`),
                  KEY  `username` (`username`(192))
            ) $charsetCollate;";
            dbDelta($sql);
        }
    }

    private static function migrateHashesTable()
    {
        global $wpdb;
        $charsetCollate = $wpdb->get_charset_collate();

        $table_name = $wpdb->prefix . 'fls_login_hashes';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            $sql = "CREATE TABLE $table_name (
				id BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
				login_hash varchar(192),
				user_id BIGINT(20) DEFAULT 0,
				used_count INT(11) DEFAULT 0,
				use_limit INT(11) DEFAULT 1,
				status varchar(20) DEFAULT 'issued',
				use_type varchar(20) DEFAULT 'magic_login',
				two_fa_code_hash varchar(100) DEFAULT '',
				ip_address varchar(20) NULL,
				redirect_intend varchar(255) NULL,
				success_ip_address varchar(50) NULL,
				country varchar(50) NULL,
				city varchar(50) NULL,
				created_by int(11) null,
				valid_till  timestamp NULL,
				created_at timestamp NULL,
				updated_at timestamp NULL,
                   KEY `created_at` (`created_at`),
                   KEY `login_hash` (`login_hash`(192)),
                   KEY `user_id` (`user_id`),
                   KEY `status` (`status`(20)),
                   KEY `use_type` (`use_type`(20))
			) $charsetCollate;";
            dbDelta($sql);
        } else {
            $table_name = $wpdb->prefix . 'fls_login_hashes';
            if(!$wpdb->get_var( "SHOW COLUMNS FROM `{$table_name}` LIKE 'two_fa_code_hash';" )) {
                $wpdb->query("ALTER TABLE {$table_name} CHANGE `two_fa_code` `two_fa_code_hash` VARCHAR(100) NULL DEFAULT '' AFTER `use_type`;");
            }
        }

        update_option('__fluent_security_db_version', '1.0.0', false);
    }

}
