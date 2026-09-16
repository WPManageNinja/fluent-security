<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Activator;
use FluentAuth\App\Helpers\Helper;

class ActivatorTest extends BaseTestCase
{
    public function testActivateSingleSite()
    {
        global $wpdb;

        // Drop tables first to test fresh creation
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}fls_auth_logs");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}fls_login_hashes");

        $result = Activator::activate(false);
        $this->assertNull($result);

        // Verify tables were created
        $logsTable = $wpdb->get_var(
            $wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->prefix . 'fls_auth_logs')
        );
        $this->assertEquals($wpdb->prefix . 'fls_auth_logs', $logsTable);

        $hashesTable = $wpdb->get_var(
            $wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->prefix . 'fls_login_hashes')
        );
        $this->assertEquals($wpdb->prefix . 'fls_login_hashes', $hashesTable);
    }

    /**
     * Updates never fire the activation hook, so the migrations that exist for sites that
     * already have the plugin reach them through maybeUpgrade() on admin_init instead.
     * The onboarding flag is the one with the most visible failure: without it, every
     * existing install would be sent into the setup wizard by the update.
     */
    public function testMaybeUpgradeRunsMigrationsOnceOnVersionChange()
    {
        delete_option('__fluent_security_version');
        delete_option(\FluentAuth\App\Services\Onboarding::OPTION);
        update_option('__fls_auth_settings', ['totp_2fa' => 'yes', 'totp_2fa_roles' => []], false);

        Activator::maybeUpgrade();

        $this->assertSame(FLUENT_AUTH_VERSION, get_option('__fluent_security_version'));
        $this->assertSame('skipped', get_option(\FluentAuth\App\Services\Onboarding::OPTION), 'a configured site is not walked into the wizard');
        $this->assertNotEmpty(get_option('__fls_auth_settings')['totp_2fa_roles'], 'the empty-means-all authenticator roles are written out');

        // A second call on the same version is a no-op: the flag written by the wizard survives.
        update_option(\FluentAuth\App\Services\Onboarding::OPTION, '2026-01-01T00:00:00+00:00', false);
        Activator::maybeUpgrade();
        $this->assertSame('2026-01-01T00:00:00+00:00', get_option(\FluentAuth\App\Services\Onboarding::OPTION));

        delete_option('__fluent_security_version');
        delete_option(\FluentAuth\App\Services\Onboarding::OPTION);
        delete_option('__fls_auth_settings');
    }

    public function testActivationHookAndUpgradeRunnerAreRegistered()
    {
        $this->assertNotFalse(has_action('admin_init', ['\\FluentAuth\\App\\Helpers\\Activator', 'maybeUpgrade']));
    }

    public function testMigrateLogsTable()
    {
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}fls_auth_logs");

        $reflection = new \ReflectionClass(Activator::class);
        $method = $reflection->getMethod('migrateLogsTable');
        $method->setAccessible(true);

        $result = $method->invoke(null);
        $this->assertNull($result);

        $table = $wpdb->get_var(
            $wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->prefix . 'fls_auth_logs')
        );
        $this->assertEquals($wpdb->prefix . 'fls_auth_logs', $table);
    }

    public function testMigrateHashesTable()
    {
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}fls_login_hashes");

        $reflection = new \ReflectionClass(Activator::class);
        $method = $reflection->getMethod('migrateHashesTable');
        $method->setAccessible(true);

        $result = $method->invoke(null);
        $this->assertNull($result);

        $table = $wpdb->get_var(
            $wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->prefix . 'fls_login_hashes')
        );
        $this->assertEquals($wpdb->prefix . 'fls_login_hashes', $table);
    }

    public function testMigrateHashesTableHasTwoFaColumn()
    {
        global $wpdb;

        // Ensure the table exists
        Activator::activate(false);

        $column = $wpdb->get_var(
            "SHOW COLUMNS FROM `{$wpdb->prefix}fls_login_hashes` LIKE 'two_fa_code_hash'"
        );
        $this->assertEquals('two_fa_code_hash', $column);
    }

    public function testMigrateSchedulesCronJobs()
    {
        // Clear any existing scheduled hooks
        wp_clear_scheduled_hook('fluent_auth_daily_tasks');
        wp_clear_scheduled_hook('fluent_auth_hourly_tasks');

        $reflection = new \ReflectionClass(Activator::class);
        $method = $reflection->getMethod('migrate');
        $method->setAccessible(true);

        $result = $method->invoke(null);
        $this->assertNull($result);

        $this->assertNotFalse(wp_next_scheduled('fluent_auth_daily_tasks'));
        $this->assertNotFalse(wp_next_scheduled('fluent_auth_hourly_tasks'));
    }

    public function testDatabaseVersionUpdate()
    {
        $reflection = new \ReflectionClass(Activator::class);
        $method = $reflection->getMethod('migrateHashesTable');
        $method->setAccessible(true);

        $method->invoke(null);

        $version = get_option('__fluent_security_db_version');
        $this->assertEquals('1.0.0', $version);
    }

    public function testActivationHookCompatibility()
    {
        try {
            Activator::activate(false);
            $this->assertTrue(true);
        } catch (\Exception $e) {
            $this->fail('Activation hook failed: ' . $e->getMessage());
        }
    }

    private function migrateTotpRoles()
    {
        $reflection = new \ReflectionClass(Activator::class);
        $method = $reflection->getMethod('migrateTotpAllowedRoles');
        $method->setAccessible(true);
        $method->invoke(null);

        Helper::resetStatics();
    }

    /**
     * An empty allow list used to mean every role and now means none. On a site that had
     * the method switched on with the field untouched, reading it the new way stops
     * asking enrolled users for the app they already set up - so the old meaning is
     * written out as roles before the new reading applies to it.
     */
    public function testItWritesOutWhatAnEmptyAllowListUsedToMean()
    {
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), [
            'totp_2fa'       => 'yes',
            'totp_2fa_roles' => []
        ]));
        Helper::resetStatics();

        $this->migrateTotpRoles();

        $roles = Helper::getSetting('totp_2fa_roles');

        $this->assertContains('administrator', $roles);
        $this->assertContains('subscriber', $roles, 'It meant every role, so every role is what it becomes.');
    }

    public function testItLeavesAChosenListAlone()
    {
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), [
            'totp_2fa'       => 'yes',
            'totp_2fa_roles' => ['editor']
        ]));
        Helper::resetStatics();

        $this->migrateTotpRoles();

        $this->assertSame(['editor'], Helper::getSetting('totp_2fa_roles'));
    }

    /**
     * With the method switched off the empty list never meant anything, so filling it in
     * would invent a policy the site never had.
     */
    public function testItLeavesTheListEmptyWhileTheMethodIsOff()
    {
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), [
            'totp_2fa'       => 'no',
            'totp_2fa_roles' => []
        ]));
        Helper::resetStatics();

        $this->migrateTotpRoles();

        $this->assertSame([], Helper::getSetting('totp_2fa_roles'));
    }
}
