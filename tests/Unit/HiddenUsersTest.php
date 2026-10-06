<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Checks\Registry;
use FluentAuth\App\Services\Checks\Users\HiddenUsersCheck;

/**
 * Accounts that exist in the table and not on the users screen.
 *
 * Every test here hides a user the way the thing this check is looking for hides one - by
 * filtering the query and leaving the row alone - because that is the only property the
 * check can rely on. A test that faked the discrepancy some other way would pass while the
 * check was looking at the wrong thing entirely.
 */
class HiddenUsersTest extends BaseTestCase
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
        Registry::reset();

        parent::tearDown();
    }

    private function only($findings)
    {
        $this->assertCount(1, $findings);

        return $findings[0]->toArray();
    }

    /**
     * Hides an account the way malware does: one clause appended to every user query, with
     * the row itself left exactly where it was.
     */
    private function hideLogin($login)
    {
        add_action('pre_user_query', function ($query) use ($login) {
            global $wpdb;

            $query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.user_login != %s", $login);
        });
    }

    /* ------------------------------------------------------------------ honest site */

    public function test_a_site_that_shows_all_its_accounts_passes()
    {
        $this->factory->user->create(['role' => 'administrator']);
        $this->factory->user->create(['role' => 'subscriber']);

        $finding = $this->only((new HiddenUsersCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
        $this->assertTrue($finding['scored']);
    }

    /**
     * A filter that adds rows is somebody merging a directory into the list, not somebody
     * hiding evidence. Only the table having more than the screen is a finding.
     */
    public function test_a_filter_that_adds_accounts_to_the_list_is_not_reported()
    {
        add_filter('users_pre_query', function ($results, $query) {
            global $wpdb;

            $query->total_users = 1 + (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users}");

            return $wpdb->get_col("SELECT ID FROM {$wpdb->users}");
        }, 10, 2);

        $this->assertEquals(Finding::STATE_PASSED, $this->only((new HiddenUsersCheck())->run())['state']);
    }

    /* ------------------------------------------------------------------ hidden accounts */

    /**
     * The role is not what makes this a finding. A hidden subscriber is an account nobody
     * reviews, and promoting it later is a single database write.
     */
    public function test_a_hidden_subscriber_is_reported_like_any_other_hidden_account()
    {
        $id = $this->factory->user->create([
            'role'       => 'subscriber',
            'user_login' => 'fls_quiet_member',
            'user_email' => 'quiet@example.com'
        ]);

        $this->hideLogin('fls_quiet_member');

        $finding = $this->only((new HiddenUsersCheck())->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);

        $details = implode("\n", $finding['details']);

        $this->assertStringContainsString('fls_quiet_member', $details);
        $this->assertStringContainsString('quiet@example.com', $details);
        $this->assertStringContainsString('subscriber', $details);
        $this->assertStringContainsString('user ID ' . $id, $details);
    }

    public function test_a_hidden_administrator_is_reported_with_its_role_shown()
    {
        $this->factory->user->create(['role' => 'administrator', 'user_login' => 'fls_ghost_admin']);

        $this->hideLogin('fls_ghost_admin');

        $finding = $this->only((new HiddenUsersCheck())->run());

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('administrator', implode("\n", $finding['details']));
    }

    public function test_every_hidden_account_is_counted_in_the_title()
    {
        $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_ghost_one']);
        $this->factory->user->create(['role' => 'editor', 'user_login' => 'fls_ghost_two']);

        $this->hideLogin('fls_ghost_one');
        $this->hideLogin('fls_ghost_two');

        $this->assertStringContainsString('2', $this->only((new HiddenUsersCheck())->run())['title']);
    }

    /**
     * The account cannot be reached from the screen it has been taken off, so the button goes
     * where it can still be reached.
     */
    public function test_the_button_opens_the_hidden_account_itself()
    {
        $id = $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_quiet_member']);

        $this->hideLogin('fls_quiet_member');

        $this->assertStringContainsString(
            'user-edit.php?user_id=' . $id,
            $this->only((new HiddenUsersCheck())->run())['url']
        );
    }

    /**
     * Knowing an account is hidden and knowing what is hiding it are different findings, and
     * only the second one tells the host's support account apart from somebody's back door.
     */
    public function test_the_file_doing_the_filtering_is_named()
    {
        $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_quiet_member']);

        $this->hideLogin('fls_quiet_member');

        $this->assertStringContainsString(
            basename(__FILE__),
            implode("\n", $this->only((new HiddenUsersCheck())->run())['details'])
        );
    }

    /* ------------------------------------------------------------------ dismissal */

    public function test_a_site_can_say_a_hidden_account_is_expected()
    {
        $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_support_user']);

        $this->hideLogin('fls_support_user');

        $check = new HiddenUsersCheck();

        $this->assertNotWPError($check->accept($check->id()));

        $this->assertEquals(Finding::STATE_ACCEPTED, $this->only($check->run())['state']);
    }

    /**
     * The reason the dismissal is keyed to the accounts rather than to the check. Agreeing
     * that the host's support account is expected must not be read as agreeing to whatever
     * turns up next month.
     */
    public function test_accepting_one_hidden_account_does_not_silence_the_next_one()
    {
        $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_support_user']);

        $this->hideLogin('fls_support_user');

        $check = new HiddenUsersCheck();
        $check->accept($check->id());

        $this->assertEquals(Finding::STATE_ACCEPTED, $this->only($check->run())['state']);

        $this->factory->user->create(['role' => 'administrator', 'user_login' => 'fls_ghost_admin']);
        $this->hideLogin('fls_ghost_admin');

        $this->assertEquals(Finding::STATE_OPEN, $this->only($check->run())['state']);
    }

    public function test_a_dismissal_can_be_taken_back()
    {
        $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_support_user']);

        $this->hideLogin('fls_support_user');

        $check = new HiddenUsersCheck();
        $check->accept($check->id());

        $this->assertNotWPError($check->unaccept($check->id()));

        $this->assertEquals(Finding::STATE_OPEN, $this->only($check->run())['state']);
    }

    public function test_a_dismissal_is_not_counted_as_satisfied()
    {
        $this->factory->user->create(['role' => 'subscriber', 'user_login' => 'fls_support_user']);

        $this->hideLogin('fls_support_user');

        $check = new HiddenUsersCheck();
        $check->accept($check->id());

        $this->assertFalse($this->only($check->run())['scored']);
    }

    public function test_another_checks_finding_id_is_refused()
    {
        $check = new HiddenUsersCheck();

        $this->assertWpErrorWithCode($check->accept('dormant_admins'), 'unknown_check');
        $this->assertWpErrorWithCode($check->unaccept('dormant_admins'), 'unknown_check');
    }

    /* ------------------------------------------------------------------ registry */

    public function test_the_screen_runs_this_check()
    {
        $this->assertArrayHasKey('hidden_users', Registry::checks());
    }
}
