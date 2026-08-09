<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Recovery\RecoveryService;

/**
 * The recovery actions.
 *
 * The most expensive surface in the plugin to get wrong: every one of these either evicts
 * somebody or writes to real inboxes. What is pinned here is mostly what must *not* happen -
 * that the person running it keeps working, that nothing is deleted, and that a run which is
 * too big for one request does not simply stop half way through with nobody the wiser.
 */
class RecoveryServiceTest extends BaseTestCase
{
    private $admin;

    public function setUp(): void
    {
        parent::setUp();

        delete_option(RecoveryService::QUEUE_OPTION);
        delete_option(RecoveryService::LOG_OPTION);

        $this->admin = $this->factory->user->create(['role' => 'administrator']);
        wp_set_current_user($this->admin);

        /* Nothing in these tests should reach a real mail server. */
        add_filter('pre_wp_mail', '__return_true');
    }

    public function tearDown(): void
    {
        remove_all_filters('pre_wp_mail');
        delete_option(RecoveryService::QUEUE_OPTION);
        delete_option(RecoveryService::LOG_OPTION);

        parent::tearDown();
    }

    /* ------------------------------------------------------------ secure now */

    public function test_securing_the_site_signs_other_people_out()
    {
        $other = $this->factory->user->create(['role' => 'editor']);

        $tokens = \WP_Session_Tokens::get_instance($other);
        $tokens->create(time() + DAY_IN_SECONDS);

        $this->assertNotEmpty(get_user_meta($other, 'session_tokens', true));

        RecoveryService::secureNow();

        $this->assertEmpty(get_user_meta($other, 'session_tokens', true));
    }

    /**
     * Turning the person running the recovery out along with everyone else reads as thorough
     * and helps nobody - an attacker holding an administrator account can do this again
     * whatever we revoke, and the one person who has to keep working is the one at the
     * keyboard.
     */
    public function test_the_person_running_it_stays_signed_in()
    {
        RecoveryService::secureNow();

        $this->assertNotEmpty(get_user_meta($this->admin, 'session_tokens', true));
    }

    public function test_securing_the_site_revokes_application_passwords()
    {
        $user = $this->factory->user->create(['role' => 'administrator']);
        \WP_Application_Passwords::create_new_application_password($user, ['name' => 'An integration']);

        $this->assertNotEmpty(\WP_Application_Passwords::get_user_application_passwords($user));

        $result = RecoveryService::secureNow();

        $this->assertEmpty(\WP_Application_Passwords::get_user_application_passwords($user));
        $this->assertEquals(1, $result['passwords']);
    }

    /**
     * Nothing on this screen deletes anybody. Somebody reaching for it is frightened, and the
     * one promise that makes it safe to press is that it can be undone by signing in again.
     */
    public function test_securing_the_site_deletes_nobody()
    {
        $before = count_users()['total_users'];

        RecoveryService::secureNow();

        $this->assertEquals($before, count_users()['total_users']);
    }

    public function test_every_action_is_written_to_the_log_with_who_did_it()
    {
        RecoveryService::secureNow();

        $history = RecoveryService::history();

        $this->assertNotEmpty($history);
        $this->assertEquals('secure_now', $history[0]['action']);
        $this->assertEquals(wp_get_current_user()->user_login, $history[0]['by']);

        $row = flsDb()->table('fls_auth_logs')->where('status', 'recovery')->first();

        $this->assertNotNull($row);
        $this->assertEquals($this->admin, (int)$row->user_id);
    }

    /**
     * The log rows have their own status so the dashboard's login figures cannot count a
     * recovery as somebody signing in.
     */
    public function test_recovery_entries_are_not_counted_as_logins()
    {
        RecoveryService::secureNow();

        $logins = flsDb()->table('fls_auth_logs')->where('status', 'success')->get();

        $this->assertEmpty($logins);
    }

    /* ------------------------------------------------------- password resets */

    public function test_administrators_can_be_mailed_on_their_own()
    {
        $this->factory->user->create(['role' => 'subscriber']);

        $result = RecoveryService::queuePasswordResets('administrators');

        $this->assertFalse(is_wp_error($result));

        $admins = count(get_users(['role' => 'administrator', 'fields' => 'ID']));

        $this->assertEquals($admins, $result['progress']['total']);
    }

    public function test_an_unknown_group_is_refused()
    {
        $this->assertWpErrorWithCode(
            RecoveryService::queuePasswordResets('everyone_i_dislike'),
            'unknown_scope'
        );
    }

    /**
     * A site with thousands of users cannot be mailed inside the request that started it. The
     * queue has to survive being interrupted, and it has to be able to say how far it got -
     * a run that dies half way through leaves nobody knowing who was told.
     */
    public function test_a_run_too_big_for_one_request_carries_on_afterwards()
    {
        for ($i = 0; $i < RecoveryService::BATCH + 5; $i++) {
            $this->factory->user->create(['role' => 'subscriber']);
        }

        $result = RecoveryService::queuePasswordResets('all');

        $this->assertTrue($result['progress']['running']);
        $this->assertEquals(RecoveryService::BATCH, $result['progress']['sent']);
        $this->assertNotFalse(wp_next_scheduled('fluent_auth_recovery_resets'));

        /* And the scheduled run picks up exactly where it left off. */
        $progress = RecoveryService::processQueue();

        $this->assertFalse($progress['running']);
        $this->assertEquals($progress['total'], $progress['sent'] + $progress['failed']);
    }

    public function test_a_finished_run_reports_itself_as_finished()
    {
        RecoveryService::queuePasswordResets('administrators');

        $progress = RecoveryService::progress();

        $this->assertFalse($progress['running']);
        $this->assertGreaterThan(0, $progress['sent']);
    }

    /* ---------------------------------------------------------- who is there */

    /**
     * The dates are the whole point of this list - an administrator created an hour before the
     * file you are worried about appeared is the most useful thing the screen can show.
     */
    public function test_administrators_are_listed_with_when_they_turned_up()
    {
        $administrators = RecoveryService::administrators();

        $this->assertNotEmpty($administrators);

        foreach ($administrators as $admin) {
            $this->assertArrayHasKey('registered_human', $admin);
            $this->assertArrayHasKey('is_new', $admin);
            $this->assertNotEmpty($admin['edit_url']);

            /*
             * A whole phrase, not a value to be introduced by the screen. "Signed in 3 hours
             * ago" and "we have no record of this account signing in" are different claims,
             * and a template prefixing both with "Last signed in" gets one of them wrong.
             */
            $this->assertNotEmpty($admin['last_login']);
            $this->assertStringContainsString('signed in', strtolower($admin['last_login']));
        }
    }

    /**
     * Never say an account has not been used. The log goes back only as far as this plugin
     * does, and "never signed in" about an account nobody was watching is how an innocent
     * colleague gets deleted at midnight.
     */
    public function test_an_account_with_no_recorded_login_is_not_called_unused()
    {
        $administrators = RecoveryService::administrators();

        $quiet = array_filter($administrators, function ($admin) {
            return stripos($admin['last_login'], 'logging began') !== false;
        });

        $this->assertNotEmpty($quiet, 'Expected at least one administrator with no logged login');

        foreach ($quiet as $admin) {
            $this->assertStringNotContainsStringIgnoringCase('never', $admin['last_login']);
        }
    }

    public function test_a_recently_created_administrator_is_flagged()
    {
        $new = $this->factory->user->create(['role' => 'administrator']);

        $flagged = array_filter(RecoveryService::administrators(), function ($admin) use ($new) {
            return $admin['id'] === $new;
        });

        $this->assertNotEmpty($flagged);
        $this->assertTrue(array_values($flagged)[0]['is_new']);
    }

    public function test_the_current_user_is_marked_as_you()
    {
        $you = array_filter(RecoveryService::administrators(), function ($admin) {
            return $admin['is_you'];
        });

        $this->assertCount(1, $you);
        $this->assertEquals($this->admin, array_values($you)[0]['id']);
    }
}
