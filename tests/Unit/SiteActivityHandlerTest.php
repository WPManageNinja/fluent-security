<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\SiteActivityHandler;

/**
 * Plugins going on and off, on the record.
 */
class SiteActivityHandlerTest extends BaseTestCase
{
    private $handler;

    public function setUp(): void
    {
        parent::setUp();
        $this->handler = new SiteActivityHandler();
        flsDb()->table('fls_auth_logs')->where('id', '>', 0)->delete();
    }

    private function rows()
    {
        return flsDb()->table('fls_auth_logs')->orderBy('id', 'ASC')->get();
    }

    public function test_it_listens_for_both_halves_of_the_event()
    {
        $this->handler->register();

        $this->assertNotFalse(has_action('activated_plugin'));
        $this->assertNotFalse(has_action('deactivated_plugin'));
        $this->assertNotFalse(has_filter('upgrader_pre_install'));
        $this->assertNotFalse(has_action('upgrader_process_complete'));
    }

    /**
     * A real plugin on disk, so the version really is read from a header rather than from
     * a double. Written on the way in, rewritten on the way out - which is what an update
     * looks like from the outside.
     */
    private function writePlugin($file, $name, $version)
    {
        $dir = dirname(WP_PLUGIN_DIR . '/' . $file);

        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents(
            WP_PLUGIN_DIR . '/' . $file,
            "<?php\n/**\n * Plugin Name: {$name}\n * Version: {$version}\n */\n"
        );
    }

    private function removePlugin($file)
    {
        $path = WP_PLUGIN_DIR . '/' . $file;

        if (file_exists($path)) {
            unlink($path);
            @rmdir(dirname($path));
        }
    }

    /** The two hooks of an update, in the order the upgrader fires them. */
    private function runUpdate($file, $newVersion, $name = 'Test Subject', $bulk = false)
    {
        $this->handler->rememberVersionBeforeUpdate(true, ['plugin' => $file]);

        if ($newVersion !== null) {
            $this->writePlugin($file, $name, $newVersion);
        }

        $hookExtra = $bulk
            ? ['type' => 'plugin', 'action' => 'update', 'bulk' => true, 'plugins' => [$file]]
            : ['type' => 'plugin', 'action' => 'update', 'plugin' => $file];

        $this->handler->recordUpdates(null, $hookExtra);
    }

    public function test_an_update_records_the_versions_it_moved_between()
    {
        $file = 'fls-update-probe/fls-update-probe.php';
        $this->writePlugin($file, 'Update Probe', '1.0.0');

        $this->runUpdate($file, '1.2.0', 'Update Probe');
        $this->removePlugin($file);

        $rows = $this->rows();
        $this->assertCount(1, $rows);
        $this->assertEquals('plugin_updated', $rows[0]->media);
        $this->assertEquals(SiteActivityHandler::STATUS, $rows[0]->status);
        $this->assertEquals('Updated Update Probe from 1.0.0 to 1.2.0.', $rows[0]->description);
    }

    public function test_a_bulk_update_reports_each_plugin_it_finished()
    {
        $file = 'fls-update-probe/fls-update-probe.php';
        $this->writePlugin($file, 'Update Probe', '1.0.0');

        $this->runUpdate($file, '1.1.0', 'Update Probe', true);
        $this->removePlugin($file);

        $this->assertCount(1, $this->rows());
        $this->assertStringContainsString('from 1.0.0 to 1.1.0', $this->rows()[0]->description);
    }

    /**
     * The completion hook fires whether the install worked or not, and an automatic update
     * restores the old files before it. Claiming an update that did not happen is worse
     * than saying nothing, so the version on disk is what decides.
     */
    public function test_a_failed_update_that_left_the_version_alone_records_nothing()
    {
        $file = 'fls-update-probe/fls-update-probe.php';
        $this->writePlugin($file, 'Update Probe', '1.0.0');

        $this->runUpdate($file, '1.0.0', 'Update Probe');
        $this->removePlugin($file);

        $this->assertCount(0, $this->rows());
    }

    /** Nothing was read on the way in, so there is nothing trustworthy to say. */
    public function test_a_completion_with_no_start_records_nothing()
    {
        $this->handler->recordUpdates(null, [
            'type'   => 'plugin',
            'action' => 'update',
            'plugin' => 'never-started/never-started.php'
        ]);

        $this->assertCount(0, $this->rows());
    }

    public function test_themes_installs_and_translations_are_left_alone()
    {
        $file = 'fls-update-probe/fls-update-probe.php';
        $this->writePlugin($file, 'Update Probe', '1.0.0');
        $this->handler->rememberVersionBeforeUpdate(true, ['plugin' => $file]);
        $this->writePlugin($file, 'Update Probe', '2.0.0');

        $this->handler->recordUpdates(null, ['type' => 'theme', 'action' => 'update', 'plugin' => $file]);
        $this->handler->recordUpdates(null, ['type' => 'plugin', 'action' => 'install', 'plugin' => $file]);
        $this->handler->recordUpdates(null, ['type' => 'translation', 'action' => 'update']);
        $this->handler->recordUpdates(null, 'not an array');

        $this->removePlugin($file);
        $this->assertCount(0, $this->rows());
    }

    /** It is a filter on the install itself: changing what it returns would cancel one. */
    public function test_remembering_the_version_never_alters_the_install()
    {
        $this->assertTrue($this->handler->rememberVersionBeforeUpdate(true, ['plugin' => 'x/x.php']));

        $error = new \WP_Error('nope', 'Cancelled elsewhere');
        $this->assertSame($error, $this->handler->rememberVersionBeforeUpdate($error, ['plugin' => 'x/x.php']));
    }

    public function test_an_activation_is_recorded_against_whoever_did_it()
    {
        $userId = $this->factory->user->create(['user_login' => 'sitemanager', 'role' => 'administrator']);
        wp_set_current_user($userId);

        $this->handler->recordActivation('hello-dolly/hello.php');

        $rows = $this->rows();
        $this->assertCount(1, $rows);

        $row = $rows[0];
        $this->assertEquals(SiteActivityHandler::STATUS, $row->status);
        $this->assertEquals('plugin_activated', $row->media);
        $this->assertEquals('sitemanager', $row->username);
        $this->assertEquals($userId, $row->user_id);
        $this->assertStringContainsString('Activated', $row->description);
    }

    public function test_a_deactivation_is_recorded_separately()
    {
        $this->handler->recordDeactivation('hello-dolly/hello.php');

        $row = $this->rows()[0];

        $this->assertEquals('plugin_deactivated', $row->media);
        $this->assertStringContainsString('Deactivated', $row->description);
    }

    /** Both rows land in the one view an admin would go looking for them in. */
    public function test_the_rows_show_up_under_site_activity()
    {
        $this->handler->recordActivation('hello-dolly/hello.php');

        $row = $this->rows()[0];

        $this->assertContains($row->status, Helper::getLogViews()['site_activity']['statuses']);
        $this->assertEquals('Site activity', Helper::getLogStatuses()[$row->status]);
        $this->assertEquals('Plugin activated', Helper::getLoginMediaLabel($row->media));
    }

    /** Across the network is a different fact about the same event, and worth saying. */
    public function test_a_network_wide_activation_says_so()
    {
        $this->handler->recordActivation('hello-dolly/hello.php', true);

        $this->assertStringContainsString('across the network', $this->rows()[0]->description);
    }

    /**
     * A plugin is deactivated on its way to being deleted, by which point its header file
     * is already gone. The row still has to name what happened.
     */
    public function test_a_plugin_whose_files_have_gone_is_still_named()
    {
        $this->handler->recordDeactivation('already-deleted/already-deleted.php');

        $row = $this->rows()[0];

        $this->assertStringContainsString('already-deleted/already-deleted.php', $row->description);
        $this->assertEquals('plugin_deactivated', $row->media);
    }

    /**
     * WP-CLI and cron reach these hooks with nobody signed in. user_id is a BIGINT that
     * rejects an empty string under strict mode, so it has to be left out, not blanked.
     */
    public function test_an_activation_with_nobody_signed_in_is_still_written()
    {
        wp_set_current_user(0);

        $this->handler->recordActivation('hello-dolly/hello.php');

        $rows = $this->rows();
        $this->assertCount(1, $rows);
        $this->assertEmpty($rows[0]->username);
        $this->assertNull($rows[0]->user_id);
    }

    /**
     * WP-CLI sets a user agent of its own, which the browser detector does not recognise.
     * The agent string is worth keeping; two columns reading "unknown" are not.
     */
    public function test_an_unrecognised_agent_is_kept_but_not_guessed_at()
    {
        $previous = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $_SERVER['HTTP_USER_AGENT'] = 'WP CLI 2.12.0';

        $this->handler->recordActivation('hello-dolly/hello.php');

        if ($previous === null) {
            unset($_SERVER['HTTP_USER_AGENT']);
        } else {
            $_SERVER['HTTP_USER_AGENT'] = $previous;
        }

        $row = $this->rows()[0];

        $this->assertEquals('WP CLI 2.12.0', $row->agent);
        $this->assertEmpty($row->browser);
        $this->assertEmpty($row->device_os);
    }

    public function test_an_empty_plugin_file_records_nothing()
    {
        $this->handler->recordActivation('');

        $this->assertCount(0, $this->rows());
    }

    /** TINYTEXT. One absurd plugin name should not cost the row. */
    public function test_a_very_long_name_is_cut_rather_than_truncating_the_row()
    {
        $this->handler->recordActivation(str_repeat('a', 500) . '/plugin.php');

        $this->assertLessThanOrEqual(255, strlen($this->rows()[0]->description));
    }
}
