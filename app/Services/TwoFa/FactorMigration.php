<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;

/**
 * Moves authenticator app enrollments out of user meta and into the factor table.
 *
 * The authenticator app was written after the last release and has never shipped, so on
 * a site that installed FluentAuth from WordPress.org there is nothing here to move.
 * What this exists for is the installs running the development branch - where real
 * secrets, real recovery codes and real people who would notice being locked out are
 * sitting in `_fls_totp_secret`.
 *
 * The failure that matters is not a migration that stops halfway. It is one that leaves
 * a user enrolled in a place nothing reads any more: they would not be locked out, they
 * would silently stop being asked for a second factor, and nobody would find out. So
 * this runs two ways. A batch moves everybody at activation, and getSecret() moves one
 * user on the way past if the batch has not reached them - which means the first thing
 * any affected login does is repair itself.
 *
 * Idempotent by construction: the meta is deleted only once its rows exist, so a run
 * that dies midway leaves the rest to the next one.
 */
class FactorMigration
{
    /**
     * The keys as they were, spelled out rather than referenced. TotpTwoFaMethod no
     * longer has constants for them, and it should not gain them back just so this
     * file can name what it is deleting.
     */
    const LEGACY_SECRET_KEY = '_fls_totp_secret';

    const LEGACY_DATA_KEY = '_fls_totp_data';

    const DONE_OPTION = '__fls_factor_migration_done';

    const BATCH_SIZE = 200;

    /**
     * @return bool
     */
    public static function isPending()
    {
        return get_option(self::DONE_OPTION) !== 'yes';
    }

    /**
     * Called from anywhere that is about to report on enrollment.
     *
     * Cheap once there is nothing left: an option read, and after the first empty batch
     * not even a query. Deliberately not hung off the settings screen's enable switch,
     * which sounds like the natural moment and is the one moment that cannot work - a
     * user can only hold a legacy enrollment on a site where the switch was already on,
     * so the transition this would listen for has already happened and will not happen
     * again.
     *
     * @return void
     */
    public static function ensureMigrated()
    {
        if (self::isPending()) {
            self::runBatch();
        }
    }

    /**
     * Moves everybody still holding a legacy enrollment.
     *
     * @return int how many users were moved
     */
    public static function runBatch()
    {
        global $wpdb;

        if (!self::isPending()) {
            return 0;
        }

        $userIds = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s LIMIT %d",
                self::LEGACY_SECRET_KEY,
                self::BATCH_SIZE
            )
        );

        if (!$userIds) {
            /*
             * Nothing left to find, so the read-through check in getSecret() can stop
             * asking. Recorded only when a query has actually come back empty - never
             * assumed from the absence of an error.
             */
            update_option(self::DONE_OPTION, 'yes', false);

            return 0;
        }

        $moved = 0;

        foreach ($userIds as $userId) {
            if (self::migrateUser((int)$userId)) {
                $moved++;
            }
        }

        return $moved;
    }

    /**
     * Moves one user, if they have anything to move.
     *
     * @param $userId int
     * @return bool
     */
    public static function migrateUser($userId)
    {
        $userId = (int)$userId;

        if (!$userId) {
            return false;
        }

        $secret = get_user_meta($userId, self::LEGACY_SECRET_KEY, true);
        $data = get_user_meta($userId, self::LEGACY_DATA_KEY, true);
        $data = is_array($data) ? $data : [];

        if (!is_string($secret) || $secret === '') {
            // Nothing confirmed. An abandoned pending secret is not worth carrying over.
            if ($data) {
                delete_user_meta($userId, self::LEGACY_DATA_KEY);
            }

            return false;
        }

        if (!FactorStore::ensureTable()) {
            return false;
        }

        /*
         * An enrollment already in the table wins. Re-inserting would give one account
         * two authenticator rows, and getSecret() would answer with whichever came
         * first - which on a half-repeated migration is not the one the user's phone
         * agrees with.
         */
        if (!FactorStore::firstForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE)) {
            $stored = FactorStore::insert([
                'user_id'    => $userId,
                'type'       => FactorStore::TYPE_TOTP,
                'status'     => FactorStore::STATUS_ACTIVE,
                'secret'     => $secret,
                'counter'    => (int)Arr::get($data, 'last_counter', 0),
                'label'      => __('Authenticator app', 'fluent-security'),
                'created_at' => Arr::get($data, 'activated_at') ? $data['activated_at'] : current_time('mysql')
            ]);

            if (is_wp_error($stored)) {
                return false;
            }
        }

        self::migrateRecoveryCodes($userId, Arr::get($data, 'recovery'));

        /*
         * Deleted last. Until this point a failure anywhere above leaves the user
         * enrolled in the old place, which is recoverable; delete first and a failure
         * would leave them enrolled in neither.
         */
        delete_user_meta($userId, self::LEGACY_SECRET_KEY);
        delete_user_meta($userId, self::LEGACY_DATA_KEY);

        do_action('fluent_auth/factor_migrated', $userId);

        return true;
    }

    /**
     * Carries over whatever recovery codes were left.
     *
     * They keep their old hashes, which were computed without the user id in them, and
     * carry a marker saying so. Rehashing is not possible - only the hashes were ever
     * stored, never the codes - so the alternative would be storing something that can
     * never match while the screen cheerfully reports ten codes remaining. RecoveryCodes
     * checks the marked rows against the old scheme, which is why a sheet somebody
     * printed before the move still works.
     *
     * @param $userId int
     * @param $hashes mixed
     * @return void
     */
    private static function migrateRecoveryCodes($userId, $hashes)
    {
        if (!is_array($hashes) || !$hashes) {
            return;
        }

        if (FactorStore::countForUser($userId, FactorStore::TYPE_RECOVERY, null)) {
            return;
        }

        foreach ($hashes as $hash) {
            if (!is_string($hash) || $hash === '') {
                continue;
            }

            FactorStore::insert([
                'user_id'    => $userId,
                'type'       => FactorStore::TYPE_RECOVERY,
                'status'     => FactorStore::STATUS_ACTIVE,
                'identifier' => $hash,
                'meta'       => ['legacy_hash' => true]
            ]);
        }
    }
}
