<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Checks\Config\DebugDisplayCheck;
use FluentAuth\App\Services\Checks\Config\HttpsCheck;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Files\BackupFilesCheck;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Checks\Users\AdminUsernameCheck;
use FluentAuth\App\Services\Checks\Users\DormantAdminCheck;
use FluentAuth\App\Services\Checks\Registry;

/**
 * The configuration, file and user advice.
 *
 * Every one of these is a check that could easily be wrong about an ordinary site, so what is
 * pinned here is mostly the restraint: the local site that is allowed to be insecure, the
 * account too new to be called abandoned, the log too young for an absence to mean anything.
 */
class AdvisoryChecksTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        delete_option(Dismissals::OPTION);
        Registry::reset();
    }

    public function tearDown(): void
    {
        delete_option(Dismissals::OPTION);

        foreach (glob(ABSPATH . 'fls-advisory-test*') ?: [] as $path) {
            unlink($path);
        }

        Registry::reset();

        parent::tearDown();
    }

    private function only($findings)
    {
        $this->assertCount(1, $findings);

        return $findings[0]->toArray();
    }

    /* ------------------------------------------------------------------- https */

    public function test_an_http_site_is_told_its_passwords_are_in_the_clear()
    {
        update_option('home', 'http://example.com');
        update_option('siteurl', 'http://example.com');

        add_filter('fluent_auth/is_local_site', '__return_false');

        $finding = $this->only((new HttpsCheck())->run());

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertNotEmpty($finding['url']);

        remove_all_filters('fluent_auth/is_local_site');
    }

    /**
     * A laptop is allowed to be insecure. Telling somebody their development site is a risk
     * every day is how they learn to skim the list that will one day matter.
     */
    public function test_a_local_site_is_not_nagged_about_https()
    {
        update_option('home', 'http://mysite.test');
        update_option('siteurl', 'http://mysite.test');

        /* Recognised from the hostname alone - almost nobody sets WP_ENVIRONMENT_TYPE. */
        $this->assertEmpty((new HttpsCheck())->run());
    }

    public function test_localhost_is_recognised_as_local_too()
    {
        update_option('home', 'http://localhost');
        update_option('siteurl', 'http://localhost');

        $this->assertEmpty((new HttpsCheck())->run());
    }

    /**
     * Being wrong in this direction silently excuses a real site from the most important row
     * on the list, so a public hostname must never be mistaken for somebody's laptop.
     */
    public function test_a_public_hostname_is_not_mistaken_for_a_local_one()
    {
        update_option('home', 'http://shop.example.com');
        update_option('siteurl', 'http://shop.example.com');

        $this->assertEquals(
            Finding::STATE_OPEN,
            $this->only((new HttpsCheck())->run())['state']
        );
    }

    /**
     * Read from the site's own addresses, not from this request: an admin reached over https
     * on a site whose public address is http still hands visitors' logins across in the clear.
     */
    public function test_an_https_site_passes()
    {
        update_option('home', 'https://example.test');
        update_option('siteurl', 'https://example.test');

        $this->assertEquals(Finding::STATE_PASSED, $this->only((new HttpsCheck())->run())['state']);
    }

    /* ----------------------------------------------------------- debug display */

    public function test_debugging_that_is_off_altogether_says_nothing_about_display()
    {
        /* WP_DEBUG is on in the test suite, so this is asserted through the check's own rule. */
        $check = new DebugDisplayCheck();

        $finding = $this->only($check->run());

        $this->assertContains($finding['state'], [Finding::STATE_PASSED, Finding::STATE_OPEN]);

        if ($finding['state'] === Finding::STATE_OPEN) {
            /* No button: this plugin does not write to wp-config.php, and says so instead. */
            $this->assertEquals('none', $finding['action']);
            $this->assertNotEmpty($finding['details']);
        }
    }

    public function test_a_config_row_can_be_declined_and_taken_back()
    {
        $check = new DebugDisplayCheck();

        if ($this->only($check->run())['state'] !== Finding::STATE_OPEN) {
            $this->markTestSkipped('Debug display is already off in this environment');
        }

        $check->accept($check->id());
        $this->assertEquals(Finding::STATE_ACCEPTED, $this->only($check->run())['state']);

        $check->unaccept($check->id());
        $this->assertEquals(Finding::STATE_OPEN, $this->only($check->run())['state']);
    }

    /* ------------------------------------------------------------ backup files */

    public function test_an_archive_in_the_web_root_is_reported()
    {
        file_put_contents(ABSPATH . 'fls-advisory-test.sql', 'DROP TABLE everything;');

        $finding = $this->only((new BackupFilesCheck())->run());

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('fls-advisory-test.sql', implode(' ', $finding['details']));
        /* Reported, never deleted - it may be the only copy of something. */
        $this->assertEquals('none', $finding['action']);
        $this->assertFileExists(ABSPATH . 'fls-advisory-test.sql');
    }

    public function test_a_wp_config_left_half_edited_is_reported()
    {
        file_put_contents(ABSPATH . 'wp-config.php.bak', '<?php // secrets');

        $found = implode(' ', $this->only((new BackupFilesCheck())->run())['details']);

        $this->assertStringContainsString('wp-config.php.bak', $found);

        unlink(ABSPATH . 'wp-config.php.bak');
    }

    /**
     * The list has to be narrow enough that it never fires on an ordinary site - a check that
     * flags normal files is one whose findings get skipped, and this is one nobody should skip.
     */
    public function test_ordinary_files_are_not_mistaken_for_backups()
    {
        file_put_contents(ABSPATH . 'fls-advisory-test.php', '<?php // a normal file');
        file_put_contents(ABSPATH . 'fls-advisory-test.txt', 'notes');

        $finding = $this->only((new BackupFilesCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
    }

    /* ------------------------------------------------------------------ users */

    public function test_an_administrator_called_admin_is_flagged()
    {
        $this->factory->user->create(['role' => 'administrator', 'user_login' => 'admin']);

        $finding = $this->only((new AdminUsernameCheck())->run());

        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertStringContainsString('admin', implode(' ', $finding['details']));
        $this->assertNotEmpty($finding['url']);
    }

    public function test_an_ordinary_username_is_not_flagged()
    {
        $this->factory->user->create(['role' => 'administrator', 'user_login' => 'jane.doe']);

        /*
         * The WordPress test install ships with an account called "admin", so the list of
         * names is narrowed here rather than the user being renamed - which also settles that
         * the filter works.
         */
        add_filter('fluent_auth/guessable_usernames', function () {
            return ['nobody-is-called-this'];
        });

        $this->assertEquals(
            Finding::STATE_PASSED,
            $this->only((new AdminUsernameCheck())->run())['state']
        );

        remove_all_filters('fluent_auth/guessable_usernames');
    }

    /**
     * The guard the whole dormant check hangs on. This site's log goes back only as far as the
     * plugin does, so on a young log "nobody has signed in for a year" would be a claim about
     * every account including the one reading it. Silence is the correct answer.
     */
    public function test_nothing_is_said_about_dormant_accounts_until_the_log_is_old_enough()
    {
        global $wpdb;

        $this->factory->user->create(['role' => 'administrator']);

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'someone',
            'status'     => 'success',
            'created_at' => gmdate('Y-m-d H:i:s', current_time('timestamp') - (30 * DAY_IN_SECONDS)),
            'updated_at' => current_time('mysql')
        ]);

        $this->assertEmpty((new DormantAdminCheck())->run());
    }

    public function test_an_account_nobody_has_used_is_flagged_once_the_log_is_old_enough()
    {
        global $wpdb;

        $old = gmdate('Y-m-d H:i:s', current_time('timestamp') - (400 * DAY_IN_SECONDS));

        $dormant = $this->factory->user->create([
            'role'            => 'administrator',
            'user_login'      => 'left.the.company',
            'user_registered' => $old
        ]);

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'someone',
            'status'     => 'success',
            'created_at' => $old,
            'updated_at' => current_time('mysql')
        ]);

        $finding = $this->only((new DormantAdminCheck())->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertStringContainsString('left.the.company', implode(' ', $finding['details']));
    }

    /**
     * Somebody added last week has obviously not signed in for a year, and saying so would be
     * nonsense.
     */
    public function test_a_brand_new_account_is_not_called_dormant()
    {
        global $wpdb;

        $old = gmdate('Y-m-d H:i:s', current_time('timestamp') - (400 * DAY_IN_SECONDS));

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'someone',
            'status'     => 'success',
            'created_at' => $old,
            'updated_at' => current_time('mysql')
        ]);

        $this->factory->user->create(['role' => 'administrator', 'user_login' => 'joined.yesterday']);

        $finding = $this->only((new DormantAdminCheck())->run());

        $this->assertStringNotContainsString('joined.yesterday', implode(' ', $finding['details'] ?: []));
    }

    public function test_a_recent_login_keeps_an_account_off_the_list()
    {
        global $wpdb;

        $old = gmdate('Y-m-d H:i:s', current_time('timestamp') - (400 * DAY_IN_SECONDS));

        $user = $this->factory->user->create([
            'role'            => 'administrator',
            'user_login'      => 'still.here',
            'user_registered' => $old
        ]);

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'someone',
            'status'     => 'success',
            'created_at' => $old,
            'updated_at' => current_time('mysql')
        ]);

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'still.here',
            'user_id'    => $user,
            'status'     => 'success',
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ]);

        $details = implode(' ', $this->only((new DormantAdminCheck())->run())['details'] ?: []);

        $this->assertStringNotContainsString('still.here', $details);
    }
}
