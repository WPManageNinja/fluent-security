<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;

/**
 * The log holds more than logins, and the screen can only name a row it has a word for.
 *
 * Both lists here drifted from what the code actually writes once already: two statuses
 * and every recovery action were being inserted without ever being declared, which left
 * those rows with no view of their own and a raw slug in the cell.
 */
class ActivityLogVocabularyTest extends BaseTestCase
{
    /**
     * The statuses inserted into fls_auth_logs, and where from. Grown by hand on purpose -
     * adding a status without adding it here is exactly the mistake this is guarding.
     */
    private function writtenStatuses()
    {
        return [
            'success'        => 'LoginSecurityHandler::handleLoginSuccess',
            'failed'         => 'LoginSecurityHandler::handleFailedLogin',
            'blocked'        => 'LoginSecurityHandler::handleBlockedLogin',
            'password_reset' => 'LoginSecurityHandler, on a reset request',
            'site_activity'  => 'RecoveryService::log and SiteActivityHandler',
            /* No longer written, but on every site that ran a recovery before the rename. */
            'recovery'       => 'RecoveryService::log, before site activity had a name',
        ];
    }

    public function test_every_status_the_log_is_written_with_has_a_word_for_it()
    {
        $declared = Helper::getLogStatuses();

        foreach ($this->writtenStatuses() as $status => $writtenBy) {
            $this->assertArrayHasKey(
                $status,
                $declared,
                sprintf('%s writes "%s", but the log screen has no label for it.', $writtenBy, $status)
            );
            $this->assertNotEmpty($declared[$status]);
        }
    }

    public function test_no_status_is_declared_that_nothing_ever_writes()
    {
        $this->assertEquals(
            array_keys($this->writtenStatuses()),
            array_keys(Helper::getLogStatuses())
        );
    }

    /**
     * Rows written before the rename have to keep a word, so the view that replaced the
     * old status has to still ask for it - otherwise every recovery a site has ever run
     * drops out of the only view that would show it.
     */
    public function test_the_view_still_reaches_rows_written_under_the_old_status()
    {
        $views = Helper::getLogViews();

        $this->assertContains('recovery', $views['site_activity']['statuses']);
        $this->assertContains('site_activity', $views['site_activity']['statuses']);
        $this->assertEquals(
            $views['site_activity']['label'],
            Helper::getLogStatuses()['recovery'],
            'An old row must show the same word as a new one.'
        );
    }

    /** The rule in the views bar is drawn where the group changes, so it changes once. */
    public function test_the_login_outcomes_are_one_unbroken_run()
    {
        $groups = array_values(array_map(function ($view) {
            return $view['group'];
        }, Helper::getLogViews()));

        $this->assertEquals(['login', 'login', 'login', 'site', 'site'], $groups);
    }

    public function test_every_view_asks_for_statuses_that_exist()
    {
        $declared = Helper::getLogStatuses();

        foreach (Helper::getLogViews() as $key => $view) {
            $this->assertNotEmpty($view['statuses'], $key . ' queries nothing.');

            foreach ($view['statuses'] as $status) {
                $this->assertArrayHasKey($status, $declared);
            }
        }
    }

    public function test_a_recovery_action_is_named_rather_than_left_as_a_slug()
    {
        $this->assertEquals('Plugin reinstalled', Helper::getLoginMediaLabel('reinstall_plugin'));
        $this->assertEquals('WordPress reinstalled', Helper::getLoginMediaLabel('reinstall_core'));
        $this->assertEquals('File deleted', Helper::getLoginMediaLabel('delete_file'));
        $this->assertEquals('Sessions cleared', Helper::getLoginMediaLabel('secure_now'));
        $this->assertEquals('Bulk password reset started', Helper::getLoginMediaLabel('password_resets'));
        $this->assertEquals('Bulk password reset finished', Helper::getLoginMediaLabel('password_resets_done'));
        $this->assertEquals('Plugin activated', Helper::getLoginMediaLabel('plugin_activated'));
        $this->assertEquals('Plugin deactivated', Helper::getLoginMediaLabel('plugin_deactivated'));
        $this->assertEquals('Plugin updated', Helper::getLoginMediaLabel('plugin_updated'));
    }

    /** Naming the recovery actions must not have disturbed the login methods. */
    public function test_the_login_methods_still_read_as_they_did()
    {
        $this->assertEquals('Login form', Helper::getLoginMediaLabel('web'));
        $this->assertEquals('Magic link', Helper::getLoginMediaLabel('magic_login'));
        $this->assertEquals('Authenticator app', Helper::getLoginMediaLabel('two_factor_totp'));
        $this->assertEquals('Some Provider', Helper::getLoginMediaLabel('some_provider'));
    }
}
