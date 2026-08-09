<?php

namespace FluentAuth\App\Services\Baseline;

/**
 * Where a site's own record of its files lives.
 *
 * One row per unit - a plugin, a theme - holding a compressed map of path to hash, rather
 * than one row per file. A large site has perhaps sixty units and thirty thousand files, and
 * the scan never asks "where is this file": it only ever asks "does this unit still match
 * what it matched before". A per-file table would be schema paid for and never queried, and
 * it would make the one thing this does do - compare a whole unit at once - a join.
 *
 * The table is created the first time somebody takes a snapshot, and never before. Most
 * people install this plugin for the login security and the customiser and will never open
 * this feature; a table nobody asked for should not appear in their database because they
 * activated something else. Everything that reads from here checks hasTable() first and
 * reports nothing when the answer is no - a feature not in use has nothing to say.
 */
class BaselineStore
{
    const DB_VERSION = '1.0.0';

    const VERSION_OPTION = '__fls_baseline_db_version';

    /**
     * @return string
     */
    public static function table()
    {
        global $wpdb;

        return $wpdb->prefix . 'fls_file_baselines';
    }

    /**
     * Whether the feature has ever been used.
     *
     * An option read rather than SHOW TABLES: this is called on every page load that draws
     * the findings list, and asking the database to describe itself for a feature nobody has
     * switched on is a query for nothing.
     *
     * @return bool
     */
    public static function hasTable()
    {
        return get_option(self::VERSION_OPTION) === self::DB_VERSION;
    }

    /**
     * Create the table, once, when somebody first takes a snapshot.
     *
     * @return bool
     */
    public static function ensureTable()
    {
        if (self::hasTable()) {
            return true;
        }

        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table = self::table();
        $charsetCollate = $wpdb->get_charset_collate();

        /*
         * `scope` is 191 rather than 255 so the unique index fits inside the key length
         * utf8mb4 allows on older MySQL. A scope is "plugin:" and a plugin's own file name,
         * which has nowhere near that much room to grow.
         */
        $sql = "CREATE TABLE $table (
            `id` BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
            `scope` VARCHAR(191) NOT NULL,
            `label` VARCHAR(191) NULL DEFAULT '',
            `version` VARCHAR(64) NULL DEFAULT '',
            `file_count` INT UNSIGNED NOT NULL DEFAULT 0,
            `hashes` LONGTEXT NULL,
            `status` VARCHAR(20) NOT NULL DEFAULT 'ok',
            `changes` LONGTEXT NULL,
            `checked_at` TIMESTAMP NULL,
            `created_at` TIMESTAMP NULL,
            `updated_at` TIMESTAMP NULL,
            UNIQUE KEY `scope` (`scope`),
            KEY `status` (`status`(20)),
            KEY `checked_at` (`checked_at`)
        ) $charsetCollate;";

        dbDelta($sql);

        if (!self::tableExists()) {
            return false;
        }

        update_option(self::VERSION_OPTION, self::DB_VERSION, false);

        return true;
    }

    /**
     * Whether the table is really there.
     *
     * Asked by selecting from it rather than with SHOW TABLES, which does not list temporary
     * tables - and the WordPress test suite rewrites every CREATE TABLE into a temporary one
     * so a test run leaves nothing behind. A check that cannot see the table it just made is
     * a check that reports this feature as broken under test and working in production, which
     * is the wrong way round for a thing to be wrong.
     *
     * @return bool
     */
    protected static function tableExists()
    {
        global $wpdb;

        $table = self::table();

        $suppress = $wpdb->suppress_errors(true);
        $wpdb->last_error = '';

        $wpdb->get_var("SELECT 1 FROM $table LIMIT 1");

        $exists = empty($wpdb->last_error);

        $wpdb->suppress_errors($suppress);
        $wpdb->last_error = '';

        return $exists;
    }

    /**
     * Store or replace one unit's record.
     *
     * @param string $scope
     * @param array $data
     * @return bool
     */
    public static function put($scope, $data)
    {
        if (!self::ensureTable()) {
            return false;
        }

        $existing = self::find($scope);
        $now = current_time('mysql');

        $row = [
            'scope'      => $scope,
            'label'      => isset($data['label']) ? $data['label'] : '',
            'version'    => isset($data['version']) ? $data['version'] : '',
            'file_count' => isset($data['file_count']) ? (int)$data['file_count'] : 0,
            'status'     => isset($data['status']) ? $data['status'] : 'ok',
            'checked_at' => $now,
            'updated_at' => $now
        ];

        if (array_key_exists('hashes', $data)) {
            $row['hashes'] = self::pack($data['hashes']);
        }

        if (array_key_exists('changes', $data)) {
            $row['changes'] = $data['changes'] ? wp_json_encode(array_values($data['changes'])) : '';
        }

        if ($existing) {
            flsDb()->table('fls_file_baselines')->where('scope', $scope)->update($row);

            return true;
        }

        $row['created_at'] = $now;

        flsDb()->table('fls_file_baselines')->insert($row);

        return true;
    }

    /**
     * @param string $scope
     * @return object|null
     */
    public static function find($scope)
    {
        if (!self::hasTable()) {
            return null;
        }

        return flsDb()->table('fls_file_baselines')->where('scope', $scope)->first();
    }

    /**
     * @param string $scope
     * @return array
     */
    public static function hashes($scope)
    {
        $row = self::find($scope);

        if (!$row || empty($row->hashes)) {
            return [];
        }

        return self::unpack($row->hashes);
    }

    /**
     * Everything known about every unit, without the hash maps.
     *
     * The blobs are the whole weight of this table and nothing outside a comparison needs
     * them, so the columns are named rather than taken wholesale.
     *
     * @return array
     */
    public static function summaries()
    {
        if (!self::hasTable()) {
            return [];
        }

        return flsDb()->table('fls_file_baselines')
            ->select(['scope', 'label', 'version', 'file_count', 'status', 'changes', 'checked_at', 'created_at'])
            ->orderBy('label', 'ASC')
            ->get();
    }

    /**
     * @return array
     */
    public static function changed()
    {
        if (!self::hasTable()) {
            return [];
        }

        return flsDb()->table('fls_file_baselines')
            ->select(['scope', 'label', 'version', 'status', 'changes', 'checked_at'])
            ->where('status', 'changed')
            ->get();
    }

    /**
     * When the snapshot was first taken.
     *
     * @return string
     */
    public static function takenAt()
    {
        if (!self::hasTable()) {
            return '';
        }

        $row = flsDb()->table('fls_file_baselines')
            ->select(['created_at'])
            ->orderBy('created_at', 'ASC')
            ->first();

        return $row ? $row->created_at : '';
    }

    /**
     * Drop the record for anything no longer installed.
     *
     * @param array $scopes the units that exist now
     * @return void
     */
    public static function forgetMissing($scopes)
    {
        if (!self::hasTable()) {
            return;
        }

        $rows = flsDb()->table('fls_file_baselines')->select(['scope'])->get();

        foreach ($rows as $row) {
            if (!in_array($row->scope, $scopes, true)) {
                flsDb()->table('fls_file_baselines')->where('scope', $row->scope)->delete();
            }
        }
    }

    /**
     * Throw the whole snapshot away.
     *
     * The table is left in place: somebody clearing a snapshot is starting again, not
     * uninstalling, and dropping it would mean the next snapshot pays to create it afresh.
     *
     * @return void
     */
    public static function clear()
    {
        if (!self::hasTable()) {
            return;
        }

        flsDb()->table('fls_file_baselines')->where('id', '>', 0)->delete();
    }

    /**
     * @param array $hashes
     * @return string
     */
    protected static function pack($hashes)
    {
        $json = wp_json_encode($hashes);

        if (!$json) {
            return '';
        }

        /*
         * Compressed, then base64'd. A plugin with three thousand files is a couple of hundred
         * kilobytes of JSON and about a fifth of that compressed; base64 gives most of that
         * back but keeps the column text, which is the difference between a value wpdb and a
         * database dump will hand back unchanged and one that may not survive a charset.
         */
        if (function_exists('gzcompress')) {
            $compressed = gzcompress($json, 6);

            if ($compressed !== false) {
                return 'gz:' . base64_encode($compressed);
            }
        }

        return $json;
    }

    /**
     * @param string $stored
     * @return array
     */
    protected static function unpack($stored)
    {
        if (strpos($stored, 'gz:') === 0) {
            if (!function_exists('gzuncompress')) {
                return [];
            }

            $raw = base64_decode(substr($stored, 3));
            $stored = $raw === false ? '' : @gzuncompress($raw);
        }

        if (!$stored) {
            return [];
        }

        $hashes = json_decode($stored, true);

        return is_array($hashes) ? $hashes : [];
    }
}
