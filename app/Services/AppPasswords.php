<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\SiteActivityHandler;

/**
 * Every application password on the site, across users.
 *
 * WordPress keeps them per user in one meta key and only ever shows a user's own on their
 * profile. Reading and revoking both go through core, so this sees exactly what the profile
 * screen sees and a revoke here is the same revoke as the button there.
 */
class AppPasswords
{
    /** Not used for this long, or never used and at least this old: worth a look. */
    const UNUSED_DAYS = 90;

    /** Users read per request. A site with more people holding these has bigger problems than this list. */
    const MAX_USERS = 1000;

    /** MAX_USERS, held where a test can lower it. */
    private static $maxUsers = self::MAX_USERS;

    private static $rows = null;

    private static $truncated = false;

    private static $hidden = 0;

    /**
     * @return array[] one row per password, newest use first, never-used last.
     */
    public static function all()
    {
        if (self::$rows !== null) {
            return self::$rows;
        }

        if (!class_exists('\WP_Application_Passwords')) {
            return [];
        }

        global $wpdb;

        self::$truncated = false;
        self::$hidden = 0;

        /*
         * Served by usermeta's meta_key index: it touches only the rows of users who have
         * ever had an application password, however many users the site has. Revoking a
         * user's last password leaves an empty array behind rather than deleting the key,
         * so that value is ruled out.
         *
         * The meta is network-wide on multisite, so there the list is this site's members:
         * joined on the site's own capabilities key, in the query, so other sites' users
         * never take a place under the cap.
         */
        $join = '';
        $joinArgs = [];
        if (is_multisite()) {
            $join = "INNER JOIN {$wpdb->usermeta} AS member ON member.user_id = pw.user_id AND member.meta_key = %s";
            $joinArgs[] = $wpdb->get_blog_prefix() . 'capabilities';
        }

        $userIds = $wpdb->get_col($wpdb->prepare(
            "SELECT DISTINCT pw.user_id FROM {$wpdb->usermeta} AS pw {$join} WHERE pw.meta_key = %s AND pw.meta_value != %s ORDER BY pw.user_id LIMIT %d",
            array_merge($joinArgs, [
                \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS,
                'a:0:{}',
                self::$maxUsers + 1
            ])
        ));

        // One row past the limit says there are more, without counting them all.
        self::$truncated = count($userIds) > self::$maxUsers;
        $userIds = array_slice($userIds, 0, self::$maxUsers);

        // Users and their meta in two queries, rather than two per user below.
        cache_users(array_map('intval', $userIds));

        $rows = [];

        foreach ($userIds as $userId) {
            $user = get_user_by('ID', (int)$userId);

            if (!$user) {
                continue;
            }

            /*
             * Core's own rule for who may see a user's application passwords. It maps to
             * edit_user, so a shop manager does not see an administrator's and, on
             * multisite, only a network administrator sees other people's. Counted, so
             * nothing claims to have checked them.
             */
            if (!current_user_can('list_app_passwords', $user->ID)) {
                self::$hidden++;
                continue;
            }

            foreach (\WP_Application_Passwords::get_user_application_passwords($user->ID) as $item) {
                $rows[] = self::format($user, $item);
            }
        }

        usort($rows, function ($a, $b) {
            return ($b['last_used'] ?: 0) <=> ($a['last_used'] ?: 0);
        });

        return self::$rows = $rows;
    }

    /**
     * @return array[] the passwords nobody has used in UNUSED_DAYS.
     */
    public static function unused()
    {
        return array_values(array_filter(self::all(), function ($row) {
            return $row['unused'];
        }));
    }

    /**
     * @return true|\WP_Error
     */
    public static function revoke($userId, $uuid)
    {
        $user = get_user_by('ID', (int)$userId);

        if (!$user) {
            return new \WP_Error('not_found', __('The user could not be found.', 'fluent-security'), ['status' => 404]);
        }

        $item = \WP_Application_Passwords::get_user_application_password($user->ID, (string)$uuid);

        // The capability core's own REST endpoint checks before deleting one.
        if (!current_user_can('delete_app_password', $user->ID, $item ? $item['uuid'] : '')) {
            return new \WP_Error('forbidden', __('You are not allowed to change this user.', 'fluent-security'), ['status' => 403]);
        }

        if (!$item) {
            return new \WP_Error('not_found', __('That application password no longer exists.', 'fluent-security'), ['status' => 404]);
        }

        $deleted = \WP_Application_Passwords::delete_application_password($user->ID, $item['uuid']);

        if (is_wp_error($deleted)) {
            return $deleted;
        }

        self::$rows = null;
        self::log($user, $item);

        return true;
    }

    /**
     * Revokes every unused password the current user may edit.
     *
     * @return int how many were revoked
     */
    public static function revokeUnused()
    {
        $count = 0;

        foreach (self::unused() as $row) {
            if (self::revoke($row['user_id'], $row['uuid']) === true) {
                $count++;
            }
        }

        return $count;
    }

    /** Whether the last read stopped at MAX_USERS, so the list may be incomplete. */
    public static function isTruncated()
    {
        return self::$truncated;
    }

    /** How many users with application passwords the current user may not see. */
    public static function hiddenUsers()
    {
        return self::$hidden;
    }

    /** Test seam: the list is read once per request. */
    public static function reset()
    {
        self::$rows = null;
        self::$truncated = false;
        self::$hidden = 0;
    }

    private static function format($user, $item)
    {
        $created = (int)($item['created'] ?? 0);
        $lastUsed = (int)($item['last_used'] ?? 0);
        $cutoff = time() - self::UNUSED_DAYS * DAY_IN_SECONDS;

        return [
            'user_id'      => $user->ID,
            'display_name' => $user->display_name,
            'user_login'   => $user->user_login,
            'roles'        => array_values(array_map('translate_user_role', array_intersect_key(wp_roles()->get_names(), array_flip((array)$user->roles)))),
            'profile_url'  => get_edit_user_link($user->ID),
            'uuid'         => $item['uuid'],
            'name'         => $item['name'],
            'created'      => $created,
            'last_used'    => $lastUsed ?: null,
            'last_ip'      => $item['last_ip'] ?? null,
            'created_on'   => $created ? wp_date(get_option('date_format'), $created) : '',
            /* translators: %s: a length of time, e.g. "3 days" */
            'last_used_ago' => $lastUsed ? sprintf(__('%s ago', 'fluent-security'), human_time_diff($lastUsed)) : '',
            'unused'       => $lastUsed ? $lastUsed < $cutoff : $created < $cutoff
        ];
    }

    private static function log($user, $item)
    {
        global $wpdb;

        $actor = wp_get_current_user();

        $data = [
            'username'    => $actor->ID ? $actor->user_login : '',
            'ip'          => Helper::getIp(),
            'status'      => SiteActivityHandler::STATUS,
            'media'       => 'app_password_revoked',
            /* translators: 1: the application password's name, 2: the user's login name */
            'description' => mb_substr(sprintf(__('Revoked the application password "%1$s" of %2$s.', 'fluent-security'), $item['name'], $user->user_login), 0, 250),
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql')
        ];

        if ($actor->ID) {
            $data['user_id'] = $actor->ID;
        }

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);
    }
}
