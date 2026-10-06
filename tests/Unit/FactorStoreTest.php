<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\FactorMigration;
use FluentAuth\App\Services\TwoFa\FactorStore;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * The shared second factor table, the codes that live in it, and the move out of user
 * meta that put them there.
 */
class FactorStoreTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        FactorStore::ensureTable();
        delete_option(FactorMigration::DONE_OPTION);
    }

    /**
     * Puts the site back to never having had the table.
     *
     * The static in hasTable() has to go with it, or the next check answers from what
     * was true before the drop.
     *
     * @return void
     */
    private function dropTable()
    {
        global $wpdb;

        $table = FactorStore::table();
        $wpdb->query("DROP TABLE IF EXISTS {$table}");
        delete_option(FactorStore::VERSION_OPTION);
        FactorStore::resetTableState();
    }

    /**
     * @param $settings array
     * @return void
     */
    private function saveSettings($settings)
    {
        wp_set_current_user($this->factory->user->create(['role' => 'administrator']));

        $request = new \WP_REST_Request();
        /*
         * Merged over the full defaults, not over whatever the option happens to hold.
         * validateSettings() rejects a partial payload outright, so a half-filled one
         * would have this helper testing the validator rather than the thing it is here
         * to test.
         */
        $request->set_param('settings', array_merge(
            \FluentAuth\App\Helpers\Helper::getAuthSettings(),
            $settings
        ));

        \FluentAuth\App\Http\Controllers\SettingsController::updateSettings($request);
        \FluentAuth\App\Helpers\Helper::resetStatics();
    }

    // -------------------------------------------------------------------- the table

    public function test_a_factor_is_stored_and_found_by_its_identifier()
    {
        $userId = $this->factory->user->create();

        $id = FactorStore::insert([
            'user_id'    => $userId,
            'type'       => FactorStore::TYPE_PASSKEY,
            'identifier' => 'abc123',
            'secret'     => 'pem',
            'meta'       => ['algorithm' => -7]
        ]);

        $this->assertIsInt($id);

        $row = FactorStore::findByIdentifier(FactorStore::TYPE_PASSKEY, 'abc123');

        $this->assertNotNull($row);
        $this->assertEquals($userId, $row->user_id);
        $this->assertSame(['algorithm' => -7], FactorStore::readMeta($row));
    }

    /**
     * The unique index, which is what makes "already registered" true under a race
     * rather than merely usually true.
     */
    public function test_two_factors_cannot_share_an_identifier()
    {
        $first = $this->factory->user->create();
        $second = $this->factory->user->create();

        FactorStore::insert([
            'user_id'    => $first,
            'type'       => FactorStore::TYPE_PASSKEY,
            'identifier' => 'shared'
        ]);

        $again = FactorStore::insert([
            'user_id'    => $second,
            'type'       => FactorStore::TYPE_PASSKEY,
            'identifier' => 'shared'
        ]);

        $this->assertWPError($again);
        $this->assertSame(1, FactorStore::countForUser($first, FactorStore::TYPE_PASSKEY));
        $this->assertSame(0, FactorStore::countForUser($second, FactorStore::TYPE_PASSKEY));
    }

    /**
     * An authenticator app has no identifier, and nulls must not collide with each
     * other the way a real value would.
     */
    public function test_factors_without_an_identifier_coexist()
    {
        $first = $this->factory->user->create();
        $second = $this->factory->user->create();

        $this->assertIsInt(FactorStore::insert([
            'user_id' => $first,
            'type'    => FactorStore::TYPE_TOTP,
            'secret'  => 'AAAA'
        ]));

        $this->assertIsInt(FactorStore::insert([
            'user_id' => $second,
            'type'    => FactorStore::TYPE_TOTP,
            'secret'  => 'BBBB'
        ]));
    }

    /**
     * A live enrollment and a half-finished one are the same type, and clearing one
     * must not take the other. This is what stops opening the setup screen a second
     * time from destroying a working second factor.
     */
    public function test_deleting_by_status_leaves_the_other_status_alone()
    {
        $userId = $this->factory->user->create();

        FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'status'  => FactorStore::STATUS_ACTIVE,
            'secret'  => 'LIVE'
        ]);

        FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'status'  => FactorStore::STATUS_PENDING,
            'secret'  => 'HALFDONE'
        ]);

        FactorStore::deleteForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING);

        $live = FactorStore::firstForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_ACTIVE);

        $this->assertNotNull($live);
        $this->assertSame('LIVE', $live->secret);
        $this->assertNull(FactorStore::firstForUser($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING));
    }

    /**
     * The status is part of the update's condition, so a second attempt on a row that
     * has already moved finds nothing to move.
     */
    public function test_a_row_can_only_be_spent_once()
    {
        $userId = $this->factory->user->create();

        $id = FactorStore::insert([
            'user_id'    => $userId,
            'type'       => FactorStore::TYPE_RECOVERY,
            'identifier' => 'hash-1'
        ]);

        $this->assertTrue(FactorStore::transition($id, FactorStore::STATUS_ACTIVE, FactorStore::STATUS_USED));
        $this->assertFalse(FactorStore::transition($id, FactorStore::STATUS_ACTIVE, FactorStore::STATUS_USED));
    }

    public function test_a_factor_cannot_be_deleted_by_a_stranger()
    {
        $owner = $this->factory->user->create();
        $stranger = $this->factory->user->create();

        $id = FactorStore::insert([
            'user_id'    => $owner,
            'type'       => FactorStore::TYPE_PASSKEY,
            'identifier' => 'mine'
        ]);

        $this->assertFalse(FactorStore::delete($id, $stranger));
        $this->assertTrue(FactorStore::delete($id, $owner));
    }

    // ---------------------------------------------------------------- recovery codes

    public function test_a_fresh_set_of_recovery_codes_is_issued_once_and_counted()
    {
        $userId = $this->factory->user->create();

        $codes = RecoveryCodes::generate($userId);

        $this->assertCount(RecoveryCodes::CODE_COUNT, $codes);
        $this->assertCount(RecoveryCodes::CODE_COUNT, array_unique($codes));
        $this->assertSame(RecoveryCodes::CODE_COUNT, RecoveryCodes::countRemaining($userId));

        foreach ($codes as $code) {
            $this->assertSame(RecoveryCodes::CODE_LENGTH, strlen($code));
        }
    }

    public function test_a_recovery_code_works_once()
    {
        $userId = $this->factory->user->create();
        $codes = RecoveryCodes::generate($userId);

        $this->assertTrue(RecoveryCodes::consume($userId, $codes[0]));
        $this->assertFalse(RecoveryCodes::consume($userId, $codes[0]));
        $this->assertSame(RecoveryCodes::CODE_COUNT - 1, RecoveryCodes::countRemaining($userId));
    }

    /**
     * Codes are bound to the account, so one lifted from somebody's printout is not a
     * way into a different account that happens to have been issued the same string.
     */
    public function test_a_recovery_code_belongs_to_one_account()
    {
        $owner = $this->factory->user->create();
        $other = $this->factory->user->create();

        $codes = RecoveryCodes::generate($owner);
        RecoveryCodes::generate($other);

        $this->assertFalse(RecoveryCodes::consume($other, $codes[0]));
        $this->assertTrue(RecoveryCodes::consume($owner, $codes[0]));
    }

    public function test_regenerating_retires_the_previous_set()
    {
        $userId = $this->factory->user->create();

        $old = RecoveryCodes::generate($userId);
        RecoveryCodes::generate($userId);

        $this->assertFalse(RecoveryCodes::consume($userId, $old[0]));
        $this->assertSame(RecoveryCodes::CODE_COUNT, RecoveryCodes::countRemaining($userId));
    }

    // ------------------------------------------------------------- creating it at all

    /**
     * Both factors ship off, so a site that never turns one on should never carry the
     * table. Saving the screen with one enabled is the moment it becomes worth having.
     */
    public function test_the_table_is_created_when_a_device_factor_is_switched_on()
    {
        $this->dropTable();

        $this->assertFalse(FactorStore::hasTable());

        $this->saveSettings(['passkey_2fa' => 'yes', 'passkey_2fa_roles' => ['administrator']]);

        $this->assertTrue(FactorStore::hasTable());
    }

    public function test_saving_with_both_factors_off_does_not_create_the_table()
    {
        $this->dropTable();

        $this->saveSettings(['totp_2fa' => 'no', 'passkey_2fa' => 'no']);

        $this->assertFalse(FactorStore::hasTable());
    }

    public function test_an_enrollment_still_creates_the_table_where_no_save_ever_happened()
    {
        $this->dropTable();

        $userId = $this->factory->user->create();

        $this->assertIsInt(FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'secret'  => 'JBSWY3DPEHPK3PXP'
        ]));

        $this->assertTrue(FactorStore::hasTable());
    }

    // -------------------------------------------------------------------- migration

    public function test_a_legacy_enrollment_is_moved_out_of_user_meta()
    {
        $userId = $this->factory->user->create();

        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');
        update_user_meta($userId, FactorMigration::LEGACY_DATA_KEY, [
            'activated_at' => '2026-01-02 03:04:05',
            'last_counter' => 99,
            'recovery'     => [hash_hmac('sha256', 'ABCDEFGHJK', wp_salt('secure_auth'))]
        ]);

        $this->assertTrue(FactorMigration::migrateUser($userId));

        $this->assertSame('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
        $this->assertSame('2026-01-02 03:04:05', TotpTwoFaMethod::getActivatedAt($userId));
        $this->assertSame('', (string)get_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, true));
        $this->assertSame('', (string)get_user_meta($userId, FactorMigration::LEGACY_DATA_KEY, true));
    }

    /**
     * The old hashes had no account in them and cannot be recomputed, so a printed
     * sheet has to keep working against the scheme it was issued under. Storing codes
     * that could never match while reporting ten remaining would be worse than losing
     * them.
     */
    public function test_recovery_codes_printed_before_the_move_still_work()
    {
        $userId = $this->factory->user->create();

        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');
        update_user_meta($userId, FactorMigration::LEGACY_DATA_KEY, [
            'recovery' => [hash_hmac('sha256', 'ABCDEFGHJK', wp_salt('secure_auth'))]
        ]);

        FactorMigration::migrateUser($userId);

        $this->assertSame(1, RecoveryCodes::countRemaining($userId));
        $this->assertTrue(RecoveryCodes::consume($userId, 'ABCDEFGHJK'));
        $this->assertFalse(RecoveryCodes::consume($userId, 'ABCDEFGHJK'));
    }

    public function test_migrating_twice_does_not_double_an_enrollment()
    {
        $userId = $this->factory->user->create();

        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');

        FactorMigration::migrateUser($userId);
        FactorMigration::migrateUser($userId);

        $this->assertSame(1, FactorStore::countForUser($userId, FactorStore::TYPE_TOTP));
    }

    /**
     * The dangerous case is not a lockout, it is an account that quietly stops being
     * asked for a second factor. Reading the secret is what repairs it.
     */
    public function test_reading_a_secret_migrates_a_user_the_batch_has_not_reached()
    {
        $userId = $this->factory->user->create();

        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');

        $this->assertTrue(TotpTwoFaMethod::isEnrolled($userId));
        $this->assertSame('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
        $this->assertSame('', (string)get_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, true));
    }

    public function test_an_abandoned_setup_is_not_carried_over_as_an_enrollment()
    {
        $userId = $this->factory->user->create();

        update_user_meta($userId, FactorMigration::LEGACY_DATA_KEY, ['pending' => 'JBSWY3DPEHPK3PXP']);

        $this->assertFalse(FactorMigration::migrateUser($userId));
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($userId));
        $this->assertSame('', (string)get_user_meta($userId, FactorMigration::LEGACY_DATA_KEY, true));
    }

    /**
     * The screens are where a missed migration would show, so they are where it is
     * asked for. This one is the reason the settings screen's enable switch is the
     * wrong trigger: the switch is already on, or nobody could have enrolled.
     */
    public function test_the_enrolled_count_migrates_before_it_answers()
    {
        $userId = $this->factory->user->create(['role' => 'administrator']);
        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');

        $this->assertSame(1, \FluentAuth\App\Http\Controllers\TwoFaController::countEnrolledUsers());
        $this->assertSame('', (string)get_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, true));
    }

    public function test_the_enrollment_list_shows_a_user_who_was_still_in_user_meta()
    {
        update_option('__fls_auth_settings', array_merge(
            (array)get_option('__fls_auth_settings'),
            ['totp_2fa' => 'yes', 'totp_2fa_roles' => ['administrator']]
        ));
        \FluentAuth\App\Helpers\Helper::resetStatics();

        $userId = $this->factory->user->create(['role' => 'administrator']);
        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');

        wp_set_current_user($userId);

        $result = \FluentAuth\App\Http\Controllers\TwoFaController::getUsers(new \WP_REST_Request());

        $rows = wp_list_filter($result['users']['data'], ['id' => $userId]);

        $this->assertCount(1, $rows, 'the migrated user should appear in the list');
        $this->assertTrue(reset($rows)['totp_enrolled']);
    }

    public function test_the_batch_records_when_there_is_nothing_left_to_move()
    {
        $userId = $this->factory->user->create();
        update_user_meta($userId, FactorMigration::LEGACY_SECRET_KEY, 'JBSWY3DPEHPK3PXP');

        $this->assertSame(1, FactorMigration::runBatch());
        $this->assertTrue(FactorMigration::isPending());

        $this->assertSame(0, FactorMigration::runBatch());
        $this->assertFalse(FactorMigration::isPending());
    }
}
