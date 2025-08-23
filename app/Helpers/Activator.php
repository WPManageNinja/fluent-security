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
