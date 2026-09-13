<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * Every second factor a user holds, in one table.
 *
 * A passkey, an authenticator app and a recovery code are three different proofs, but
 * they are the same kind of record: something a user registered, that a login can ask
 * for, that can be spent or revoked, and that somebody eventually has to list. Keeping
 * them apart meant asking two different storage layers the same question and getting
 * answers that could not be combined - the enrollment screen counted authenticator apps
 * and silently ignored passkeys, because one lived in user meta and the other did not.
 *
 * What is shared gets a column; what belongs to one type goes in `meta` as JSON. The
 * split is not by whether a field is common but by whether it ever changes on its own:
 * `counter`, `status` and `last_used_at` are written during a login and must not be
 * part of a blob that a concurrent request could rewrite whole. Everything in `meta` -
 * a passkey's transports, its aaguid - is written once at registration and never again.
 *
 * How each type uses the columns:
 *
 *   passkey   identifier = credential id, secret = public key PEM, counter = signature
 *             counter, meta = algorithm, transports, aaguid, backup flag
 *   totp      identifier = null, secret = the base32 shared secret, counter = the last
 *             time step spent. A setup that was started but never confirmed is the same
 *             row with status `pending`, which is what keeps an abandoned one from
 *             counting as an enrollment
 *   recovery  identifier = the code's hash, one row per code, status `used` once spent
 */
class FactorStore
{
    const DB_VERSION = '1.0.0';

    const VERSION_OPTION = '__fls_auth_factors_db_version';

    const TYPE_PASSKEY = 'passkey';

    const TYPE_TOTP = 'totp';

    const TYPE_RECOVERY = 'recovery';

    const STATUS_ACTIVE = 'active';

    const STATUS_PENDING = 'pending';

    const STATUS_USED = 'used';

    /**
     * @return string
     */
    public static function table()
    {
        global $wpdb;

        return $wpdb->prefix . 'fls_auth_factors';
    }

    /**
     * Whether the option says the table exists and the database agrees.
     *
     * @var bool|null
     */
    private static $confirmed = null;

    /**
     * @return bool
     */
    public static function hasTable()
    {
        if (get_option(self::VERSION_OPTION) !== self::DB_VERSION) {
            return false;
        }

        /*
         * The option says the table was made, which is not the same as it being there
         * now - a partial restore or a stray DROP leaves the option behind. Confirmed
         * once, because the alternative is every second factor query failing against a
         * table that is not there while the option insists it is.
         */
        if (self::$confirmed === null) {
            self::$confirmed = self::tableExists();
        }

        return self::$confirmed;
    }

    /**
     * Forgets what was confirmed.
     *
     * Needed because the answer can change within one request in both directions: the
     * table is made partway through by ensureTable(), or dropped under a long running
     * process. A cached "no" surviving its own creation would leave every read after it
     * reporting an empty site while the rows are sitting right there.
     *
     * @return void
     */
    public static function resetTableState()
    {
        self::$confirmed = null;
    }

    /**
     * Created on demand rather than on activation: activation does not run when a site
     * updates the plugin, so a table made there would exist on new installs and be
     * missing on every site that already had it.
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
         * `identifier` is unique per type, which is what refuses a passkey credential
         * already registered to somebody else - WebAuthn section 7.1 step 20, enforced
         * by the database rather than by a check that could race. An authenticator app
         * has no such identifier and stores null; MySQL does not collide nulls, so any
         * number of them coexist.
         *
         * 180 characters of it are indexed so the key fits the length utf8mb4 allows on
         * older MySQL. Credential ids run to 86 characters and a recovery hash to 64,
         * so nothing real is ever truncated.
         */
        $sql = "CREATE TABLE $table (
            `id` BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
            `user_id` BIGINT UNSIGNED NOT NULL DEFAULT 0,
            `type` VARCHAR(20) NOT NULL DEFAULT '',
            `status` VARCHAR(20) NOT NULL DEFAULT 'active',
            `identifier` VARCHAR(255) NULL DEFAULT NULL,
            `secret` TEXT NULL,
            `counter` BIGINT UNSIGNED NOT NULL DEFAULT 0,
            `label` VARCHAR(191) NULL DEFAULT '',
            `meta` TEXT NULL,
            `last_used_at` TIMESTAMP NULL,
            `created_at` TIMESTAMP NULL,
            `updated_at` TIMESTAMP NULL,
            UNIQUE KEY `type_identifier` (`type`(20), `identifier`(180)),
            KEY `user_factor` (`user_id`, `type`(20), `status`(20))
        ) $charsetCollate;";

        dbDelta($sql);

        if (!self::tableExists()) {
            return false;
        }

        update_option(self::VERSION_OPTION, self::DB_VERSION, false);

        /*
         * Recorded rather than left for the next hasTable() to rediscover: it has just
         * been proved above, and leaving it null means the very next read asks the
         * database the same question again.
         */
        self::$confirmed = true;

        return true;
    }

    /**
     * Whether the table is really there.
     *
     * Selected from rather than asked for with SHOW TABLES, which does not list
     * temporary tables - and the WordPress test suite rewrites every CREATE TABLE into
     * a temporary one. See BaselineStore, which learned this first.
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
     * @param $user \WP_User|int
     * @param $type string|null
     * @param $status string|null null for any
     * @return array
     */
    public static function forUser($user, $type = null, $status = self::STATUS_ACTIVE)
    {
        $userId = self::resolveUserId($user);

        if (!$userId || !self::hasTable()) {
            return [];
        }

        $query = flsDb()->table('fls_auth_factors')->where('user_id', $userId);

        if ($type !== null) {
            $query = $query->where('type', $type);
        }

        if ($status !== null) {
            $query = $query->where('status', $status);
        }

        return $query->orderBy('id', 'ASC')->get();
    }

    /**
     * @param $user \WP_User|int
     * @param $type string
     * @param $status string|null
     * @return int
     */
    public static function countForUser($user, $type, $status = self::STATUS_ACTIVE)
    {
        return count(self::forUser($user, $type, $status));
    }

    /**
     * The single row of a type that only ever has one - an authenticator app.
     *
     * @param $user \WP_User|int
     * @param $type string
     * @param $status string|null
     * @return object|null
     */
    public static function firstForUser($user, $type, $status = self::STATUS_ACTIVE)
    {
        $rows = self::forUser($user, $type, $status);

        return $rows ? $rows[0] : null;
    }

    /**
     * @param $type string
     * @param $identifier string
     * @return object|null
     */
    public static function findByIdentifier($type, $identifier)
    {
        if (!is_string($identifier) || $identifier === '' || !self::hasTable()) {
            return null;
        }

        $row = flsDb()->table('fls_auth_factors')
            ->where('type', $type)
            ->where('identifier', $identifier)
            ->first();

        return $row ? $row : null;
    }

    /**
     * @param $id int
     * @param $userId int
     * @return object|null
     */
    public static function findOwned($id, $userId)
    {
        if (!$id || !$userId || !self::hasTable()) {
            return null;
        }

        $row = flsDb()->table('fls_auth_factors')
            ->where('id', (int)$id)
            ->where('user_id', (int)$userId)
            ->first();

        return $row ? $row : null;
    }

    /**
     * @param $data array
     * @return int|\WP_Error the new row id
     */
    public static function insert($data)
    {
        if (!self::ensureTable()) {
            return new \WP_Error('no_table', __('The second factor store could not be created', 'fluent-security'));
        }

        global $wpdb;

        $row = array_merge([
            'user_id'    => 0,
            'type'       => '',
            'status'     => self::STATUS_ACTIVE,
            'identifier' => null,
            'secret'     => '',
            'counter'    => 0,
            'label'      => '',
            'meta'       => null,
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ], $data);

        if (is_array($row['meta'])) {
            $row['meta'] = $row['meta'] ? wp_json_encode($row['meta']) : null;
        }

        /*
         * Written with $wpdb rather than the query builder, for two reasons that both
         * matter here. The builder turns a null into an empty string, and an empty
         * string is a value - so every authenticator app row, which has no identifier,
         * would collide with every other one on the unique index. And the builder's
         * insert() reports nothing at all, while this returns false, which is the only
         * way to tell a rejected duplicate from a successful write.
         *
         * Errors are silenced because a duplicate identifier is an expected answer -
         * section 7.1 step 20 asking the database to refuse a credential already on
         * file - rather than something worth printing into somebody's login page.
         */
        $suppress = $wpdb->suppress_errors(true);

        $written = $wpdb->insert(self::table(), $row);

        $wpdb->suppress_errors($suppress);
        $wpdb->last_error = '';

        if ($written === false) {
            return new \WP_Error(
                'factor_not_stored',
                __('That second factor is already registered', 'fluent-security')
            );
        }

        return (int)$wpdb->insert_id;
    }

    /**
     * @param $id int
     * @param $changes array
     * @return void
     */
    public static function update($id, $changes)
    {
        if (!$id || !self::hasTable()) {
            return;
        }

        if (isset($changes['meta']) && is_array($changes['meta'])) {
            $changes['meta'] = $changes['meta'] ? wp_json_encode($changes['meta']) : null;
        }

        $changes['updated_at'] = current_time('mysql');

        flsDb()->table('fls_auth_factors')->where('id', (int)$id)->update($changes);
    }

    /**
     * Spends a row, and says whether this caller is the one that spent it.
     *
     * The status is part of the condition rather than checked beforehand, so two
     * requests arriving together cannot both be told they consumed the same recovery
     * code. Only the one whose update actually matched a row is.
     *
     * @param $id int
     * @param $from string the status it must currently be in
     * @param $to string
     * @return bool
     */
    public static function transition($id, $from, $to)
    {
        global $wpdb;

        if (!$id || !self::hasTable()) {
            return false;
        }

        $table = self::table();

        $updated = $wpdb->query(
            $wpdb->prepare(
                "UPDATE $table SET `status` = %s, `last_used_at` = %s, `updated_at` = %s
                 WHERE `id` = %d AND `status` = %s",
                $to,
                current_time('mysql'),
                current_time('mysql'),
                (int)$id,
                $from
            )
        );

        return $updated === 1;
    }

    /**
     * @param $id int
     * @param $counter int
     * @return void
     */
    public static function touch($id, $counter = null)
    {
        $changes = ['last_used_at' => current_time('mysql')];

        if ($counter !== null) {
            $changes['counter'] = (int)$counter;
        }

        self::update($id, $changes);
    }

    /**
     * @param $id int
     * @param $user \WP_User|int whose factor it must be
     * @return bool
     */
    public static function delete($id, $user)
    {
        $userId = self::resolveUserId($user);

        /*
         * Looked up before it is removed, and both queries carry the owner. The lookup
         * is what makes the answer meaningful - this query builder's delete() reports
         * nothing at all. The delete stays scoped anyway: a check followed by an
         * unscoped delete is one refactor away from removing somebody else's factor.
         */
        if (!self::findOwned($id, $userId)) {
            return false;
        }

        flsDb()->table('fls_auth_factors')
            ->where('id', (int)$id)
            ->where('user_id', $userId)
            ->delete();

        return true;
    }

    /**
     * @param $user \WP_User|int
     * @param $type string|null null for every type
     * @param $status string|null null for every status - see the warning below
     * @return void
     */
    public static function deleteForUser($user, $type = null, $status = null)
    {
        $userId = self::resolveUserId($user);

        if (!$userId || !self::hasTable()) {
            return;
        }

        $query = flsDb()->table('fls_auth_factors')->where('user_id', $userId);

        if ($type !== null) {
            $query = $query->where('type', $type);
        }

        /*
         * Name a status unless you really do mean all of them. A half-finished setup and
         * a live enrollment are two rows of the same type, so clearing "the user's totp"
         * without saying which takes the working one away with the abandoned one - which
         * turns opening the setup page a second time into losing your second factor.
         */
        if ($status !== null) {
            $query = $query->where('status', $status);
        }

        $query->delete();
    }

    /**
     * The ids of everybody holding a given factor.
     *
     * Exists because WP_User_Query cannot join a table it does not know about. The
     * enrollment screen and the dashboard tile ask this, then hand the ids back to
     * WP_User_Query as an include or an exclude - which keeps one place responsible for
     * what "enrolled" means rather than spreading the definition across both screens.
     *
     * @param $types array|string
     * @param $status string|null
     * @return array
     */
    public static function getEnrolledUserIds($types, $status = self::STATUS_ACTIVE)
    {
        if (!self::hasTable()) {
            return [];
        }

        $query = flsDb()->table('fls_auth_factors')
            ->select('user_id')
            ->whereIn('type', (array)$types);

        if ($status !== null) {
            $query = $query->where('status', $status);
        }

        $rows = $query->groupBy('user_id')->get();

        $ids = [];

        foreach ($rows as $row) {
            $ids[] = (int)$row->user_id;
        }

        return $ids;
    }

    /**
     * @param $row object
     * @return array
     */
    public static function readMeta($row)
    {
        if (!$row || empty($row->meta)) {
            return [];
        }

        $meta = json_decode($row->meta, true);

        return is_array($meta) ? $meta : [];
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    private static function resolveUserId($user)
    {
        if ($user instanceof \WP_User) {
            return (int)$user->ID;
        }

        return is_numeric($user) ? (int)$user : 0;
    }
}
