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
     * There is no upgrade routine, and there is nothing for one to do.
     *
     * Activation only ever runs on a site switching the plugin on, so a table that has to
     * reach a site that already has the plugin is made on first use instead - see
     * FactorStore::ensureTable(). Nothing here records a version to compare against on
     * later requests, and nothing here rewrites settings.
     */
    public function testActivationLeavesNoUpgradeStateBehind()
    {
        delete_option('__fluent_security_version');
        update_option('__fls_auth_settings', ['totp_2fa' => 'yes', 'totp_2fa_roles' => []], false);

        Activator::activate(false);

        $this->assertFalse(get_option('__fluent_security_version'));
        $this->assertFalse(get_option('__fls_auth_onboarded'));
        $this->assertSame(
            ['totp_2fa' => 'yes', 'totp_2fa_roles' => []],
            get_option('__fls_auth_settings')
        );

        delete_option('__fls_auth_settings');
    }

    /** Nothing of this plugin's runs on admin_init to catch a site up on an update. */
    public function testNoUpgradeRunnerIsHooked()
    {
        $this->assertFalse(has_action('admin_init', ['\\FluentAuth\\App\\Helpers\\Activator', 'maybeUpgrade']));
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
}
