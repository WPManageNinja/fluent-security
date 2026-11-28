<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\AppPasswordsController;
use FluentAuth\App\Services\AppPasswords;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Checks\Users\AppPasswordsCheck;

class AppPasswordsTest extends BaseTestCase
{
    private $admin;

    public function setUp(): void
    {
        parent::setUp();
        add_filter('wp_is_application_passwords_available', '__return_true');
        AppPasswords::reset();

        $this->admin = self::factory()->user->create(['role' => 'administrator', 'user_login' => 'owner']);
        wp_set_current_user($this->admin);
    }

    public function tearDown(): void
    {
        remove_filter('wp_is_application_passwords_available', '__return_true');
        AppPasswords::reset();
        parent::tearDown();
    }

    /**
     * @return string the new password's uuid
     */
    private function addPassword($userId, $name, $createdDaysAgo = 0, $lastUsedDaysAgo = null)
    {
        [, $item] = \WP_Application_Passwords::create_new_application_password($userId, ['name' => $name]);

        $all = get_user_meta($userId, \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, true);
        foreach ($all as &$row) {
            if ($row['uuid'] === $item['uuid']) {
                $row['created'] = time() - $createdDaysAgo * DAY_IN_SECONDS;
                $row['last_used'] = $lastUsedDaysAgo === null ? null : time() - $lastUsedDaysAgo * DAY_IN_SECONDS;
                $row['last_ip'] = $lastUsedDaysAgo === null ? null : '203.0.113.4';
            }
        }
        update_user_meta($userId, \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, $all);
        AppPasswords::reset();

        return $item['uuid'];
    }

    public function test_it_lists_every_users_passwords_with_who_and_when()
    {
        $editor = self::factory()->user->create(['role' => 'editor', 'user_login' => 'jane']);
        $this->addPassword($editor, 'Zapier', 300, 240);
        $this->addPassword($this->admin, 'Mobile app', 30, 2);

        $rows = AppPasswords::all();

        $this->assertCount(2, $rows);
        $this->assertSame('Mobile app', $rows[0]['name'], 'Most recently used first');
        $this->assertSame('jane', $rows[1]['user_login']);
        $this->assertSame('203.0.113.4', $rows[1]['last_ip']);
        $this->assertTrue($rows[1]['unused']);
        $this->assertFalse($rows[0]['unused']);
    }

    public function test_never_used_counts_as_unused_only_once_it_is_old()
    {
        $this->addPassword($this->admin, 'Fresh, never used', 10);
        $this->addPassword($this->admin, 'Old, never used', 120);

        $unused = AppPasswords::unused();

        $this->assertCount(1, $unused);
        $this->assertSame('Old, never used', $unused[0]['name']);
    }

    /** Core leaves an empty array behind when someone revokes their last password. */
    public function test_a_user_whose_passwords_were_all_revoked_is_not_listed()
    {
        $uuid = $this->addPassword($this->admin, 'Gone', 5);
        \WP_Application_Passwords::delete_application_password($this->admin, $uuid);
        AppPasswords::reset();

        $this->assertSame([], AppPasswords::all());
    }

    public function test_revoking_deletes_through_core_and_logs_it()
    {
        global $wpdb;
        $editor = self::factory()->user->create(['role' => 'editor', 'user_login' => 'jane']);
        $uuid = $this->addPassword($editor, 'Zapier', 300, 240);

        $this->assertTrue(AppPasswords::revoke($editor, $uuid));

        $this->assertNull(\WP_Application_Passwords::get_user_application_password($editor, $uuid));
        $log = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE media = 'app_password_revoked' ORDER BY id DESC LIMIT 1");
        $this->assertNotNull($log);
        $this->assertStringContainsString('"Zapier" of jane', $log->description);
        $this->assertSame('owner', $log->username);
    }

    public function test_revoking_someone_you_cannot_edit_is_refused()
    {
        $other = self::factory()->user->create(['role' => 'administrator']);
        $uuid = $this->addPassword($other, 'Theirs', 5);

        $editor = self::factory()->user->create(['role' => 'editor']);
        wp_set_current_user($editor);

        $result = AppPasswords::revoke($other, $uuid);

        $this->assertWPError($result);
        $this->assertSame('forbidden', $result->get_error_code());
        $this->assertNotNull(\WP_Application_Passwords::get_user_application_password($other, $uuid));
    }

    public function test_revoke_unused_leaves_the_ones_in_use()
    {
        $kept = $this->addPassword($this->admin, 'In use', 300, 3);
        $this->addPassword($this->admin, 'Stale', 300, 200);
        $this->addPassword($this->admin, 'Never', 200);

        $this->assertSame(2, AppPasswords::revokeUnused());

        AppPasswords::reset();
        $left = AppPasswords::all();
        $this->assertCount(1, $left);
        $this->assertSame($kept, $left[0]['uuid']);
    }

    /** The list reads users and meta in a fixed number of queries, however many users hold passwords. */
    public function test_listing_does_not_query_per_user()
    {
        global $wpdb;

        foreach (range(1, 25) as $i) {
            $this->addPassword(self::factory()->user->create(), 'App ' . $i, 10, 1);
        }

        wp_cache_flush();
        AppPasswords::reset();

        $before = $wpdb->num_queries;
        $rows = AppPasswords::all();
        $queries = $wpdb->num_queries - $before;

        $this->assertCount(25, $rows);
        $this->assertLessThan(10, $queries, "Listing 25 users took $queries queries");
    }

    public function test_the_endpoint_returns_the_list_and_whether_they_can_sign_in()
    {
        $this->addPassword($this->admin, 'Mobile app', 30, 2);

        $result = AppPasswordsController::index(new \WP_REST_Request('GET', '/fluent-auth/app-passwords'));

        $this->assertCount(1, $result['passwords']);
        $this->assertSame(90, $result['unused_days']);
        $this->assertTrue($result['available']);
    }

    public function test_the_security_check_points_at_unused_passwords()
    {
        $check = new AppPasswordsCheck();

        $this->assertSame(Finding::STATE_PASSED, $check->run()[0]->toArray()['state']);

        $this->addPassword($this->admin, 'Stale', 300, 200);
        $finding = $check->run()[0]->toArray();

        $this->assertSame(Finding::STATE_OPEN, $finding['state']);
        $this->assertSame('settings_app_passwords', $finding['route']);
        $this->assertStringContainsString('"Stale" of owner', implode(' ', $finding['details']));
    }
}
