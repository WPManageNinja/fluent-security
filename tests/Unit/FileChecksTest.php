<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Files\DropInsCheck;
use FluentAuth\App\Services\Checks\Files\MuPluginsCheck;
use FluentAuth\App\Services\Checks\Files\UploadsExecutionCheck;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Checks\Registry;

/**
 * The file checks.
 *
 * What is being pinned here is mostly restraint: when these say nothing, when they ask rather
 * than accuse, and - for the probe - that they never report a verdict they did not test for.
 */
class FileChecksTest extends BaseTestCase
{
    private $muDir;

    public function setUp(): void
    {
        parent::setUp();

        Registry::reset();
        delete_option('__fls_integrity_ignore_lists');
        delete_option('__fls_dismissed_checks');
        delete_transient(UploadsExecutionCheck::CACHE_KEY);

        $this->muDir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        if (!is_dir($this->muDir)) {
            mkdir($this->muDir, 0755, true);
        }

        array_map('unlink', glob($this->muDir . '/fls-test-*.php') ?: []);
    }

    public function tearDown(): void
    {
        array_map('unlink', glob($this->muDir . '/fls-test-*.php') ?: []);
        delete_transient(UploadsExecutionCheck::CACHE_KEY);
        Registry::reset();

        parent::tearDown();
    }

    private function writeMuPlugin($name, $body)
    {
        file_put_contents($this->muDir . '/fls-test-' . $name . '.php', $body);
    }

    private function muScope()
    {
        return AcceptedFiles::toRelative(
            defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins'
        );
    }

    private function only($findings)
    {
        $this->assertCount(1, $findings);

        return $findings[0]->toArray();
    }

    /* ------------------------------------------------------------ mu-plugins */

    /**
     * The first sight of a file here is not evidence of anything. Hosts ship mu-plugins and
     * developers write them; saying anything at all on day one would be saying it about the
     * host, and being wrong once is how a security tool teaches people to ignore it.
     *
     * The stronger claim is that the row is not merely quiet but not outstanding: it used to
     * be scored while open, so a site sat below full marks until somebody clicked a button
     * about files they did not put there.
     */
    public function test_the_first_sight_of_these_files_is_recorded_rather_than_reported()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $finding = $this->only((new MuPluginsCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
        $this->assertNotEmpty(AcceptedFiles::all());
        $this->assertTrue(AcceptedFiles::hasBaseline($this->muScope()));
    }

    /**
     * An empty folder is a pass too, and says a different thing.
     */
    public function test_nothing_here_at_all_is_a_pass()
    {
        $finding = $this->only((new MuPluginsCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
        $this->assertStringContainsString('Nothing loads', $finding['title']);
    }

    /**
     * The claim this check can actually stand behind: not that a file is suspicious, but that
     * it is not the file that was here.
     */
    public function test_a_file_that_changes_after_the_baseline_is_the_alarm()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $check = new MuPluginsCheck();
        $check->run();

        $this->writeMuPlugin('one', '<?php eval($_POST["x"]); // not that any more');

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('has changed', $finding['title']);
    }

    /**
     * A file dropped in after the fact is the same event wearing different clothes, and the
     * more common of the two - so it is the same alarm, not a milder one.
     */
    public function test_a_file_that_appears_after_the_baseline_is_the_same_alarm()
    {
        $this->writeMuPlugin('one', '<?php // known');

        $check = new MuPluginsCheck();
        $check->run();

        $this->writeMuPlugin('two', '<?php // brand new');

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('fls-test-two.php', implode(' ', $finding['details']));

        /* One file is "A new file", not "1 new files". */
        $this->assertStringNotContainsString('1 new files', $finding['title']);
    }

    /**
     * The hole a bare "are there any hashes here" test would leave open. Emptying the folder
     * prunes every entry under the scope, and if that read as never-recorded then deleting
     * the host's files and dropping in your own would be silently blessed - which is a thing
     * an attacker can arrange and a host cannot.
     */
    public function test_emptying_the_folder_does_not_win_a_fresh_baseline()
    {
        $this->writeMuPlugin('one', '<?php // known');

        $check = new MuPluginsCheck();
        $check->run();

        unlink($this->muDir . '/fls-test-one.php');
        $check->run();

        $this->assertEmpty(AcceptedFiles::all());
        $this->assertTrue(AcceptedFiles::hasBaseline($this->muScope()));

        $this->writeMuPlugin('evil', '<?php eval($_POST["x"]);');

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
    }

    /**
     * One check must not forget another's record.
     *
     * The drop-ins live loose in wp-content, so "everything under /wp-content/" is a prefix
     * that covers the mu-plugins directory too. Pruning on that prefix had the drop-ins check
     * wiping the mu-plugins hashes on every run - and the failure is silent and in the worst
     * direction: the next run finds no baseline, records whatever is there now, and a planted
     * file comes back reading as expected.
     */
    public function test_the_drop_ins_check_does_not_forget_what_the_mu_plugins_check_recorded()
    {
        $this->writeMuPlugin('one', '<?php // known');

        (new MuPluginsCheck())->run();

        $recorded = AcceptedFiles::all();

        $this->assertNotEmpty($recorded);

        (new DropInsCheck())->run();

        $after = AcceptedFiles::all();

        /*
         * Every mu-plugins entry survives, hash and all. Asserted as a subset rather than as
         * equality, because the drop-ins check legitimately adds its own entries in the same
         * pass - the test suite's install has a db.php.
         */
        foreach ($recorded as $path => $hash) {
            $this->assertArrayHasKey($path, $after, $path . ' was forgotten by another check');
            $this->assertEquals($hash, $after[$path]);
        }

        $this->assertTrue(AcceptedFiles::hasBaseline($this->muScope()));

        /* And the record still does its job afterwards. */
        $this->writeMuPlugin('one', '<?php eval($_POST["x"]);');

        $this->assertEquals(
            Finding::SEVERITY_FIX,
            $this->only((new MuPluginsCheck())->run())['severity']
        );
    }

    /**
     * Accepting is still how somebody says "yes, that was me" to an alarm they have looked at.
     */
    public function test_accepting_an_alarm_settles_it()
    {
        $this->writeMuPlugin('one', '<?php // known');

        $check = new MuPluginsCheck();
        $check->run();

        $this->writeMuPlugin('two', '<?php // brand new');

        $this->assertEquals(Finding::STATE_OPEN, $this->only($check->run())['state']);

        $check->accept($check->id());

        $this->assertEquals(Finding::STATE_PASSED, $this->only($check->run())['state']);
    }

    public function test_an_acceptance_can_be_taken_back()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $check = new MuPluginsCheck();
        $check->run();

        $this->assertFalse(is_wp_error($check->unaccept($check->id())));

        $this->assertEmpty(AcceptedFiles::all());
    }

    public function test_a_recorded_file_that_is_deleted_is_forgotten()
    {
        $this->writeMuPlugin('one', '<?php // known');

        $check = new MuPluginsCheck();
        $check->run();

        $this->assertNotEmpty(AcceptedFiles::all());

        unlink($this->muDir . '/fls-test-one.php');
        $check->run();

        $this->assertEmpty(AcceptedFiles::all());
    }

    /* --------------------------------------------------------- uploads probe */

    /**
     * The whole design of this check. A probe that cannot complete must say so - reporting a
     * failed test as blocked is an assurance nobody checked, and as executing it is a false
     * alarm. Both are worse than admitting the test did not run.
     */
    public function test_a_probe_that_cannot_complete_says_so_and_is_not_scored()
    {
        add_filter('pre_http_request', function () {
            return new \WP_Error('http_request_failed', 'Connection refused');
        });

        $finding = $this->only((new UploadsExecutionCheck())->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertFalse($finding['scored']);
        $this->assertStringContainsString('could not test', strtolower($finding['title']));

        remove_all_filters('pre_http_request');
    }

    public function test_a_folder_that_runs_php_is_the_one_thing_here_worth_shouting_about()
    {
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 200], 'body' => 'FLS-EXECUTED'];
        });

        $finding = $this->only((new UploadsExecutionCheck())->run());

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertTrue($finding['scored']);

        remove_all_filters('pre_http_request');
    }

    /**
     * Setting this one aside is not the same promise as dismissing anything else on the list.
     *
     * The answer here was measured rather than inferred, so the row cannot move to the settled
     * list without the plugin filing a proven finding under things that are fine. What the
     * reader is saying is "my host will not change this", and all that can honestly follow is
     * that it stops being counted.
     */
    public function test_setting_the_uploads_finding_aside_stops_it_scoring_without_burying_it()
    {
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 200], 'body' => 'FLS-EXECUTED'];
        });

        $check = new UploadsExecutionCheck();

        $before = $this->only($check->run());

        $this->assertEquals('aside', $before['dismiss']);
        $this->assertFalse(is_wp_error($check->accept($check->id())));

        $finding = $this->only($check->run());

        /* Still open, still saying the same thing, and no longer red or counted. */
        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertFalse($finding['scored']);
        $this->assertEquals('undo', $finding['dismiss']);
        $this->assertStringContainsString('still true', $finding['why']);

        /*
         * Whatever the row could offer before, it still offers - so somebody who moves host,
         * or whose host finally answers, does not have to undo a decision before they can act.
         * Asserted against the row as it was rather than against a literal, because what is on
         * offer depends on whether this server is one the rule can be written for.
         */
        $this->assertEquals($before['action'], $finding['action']);
        $this->assertEquals($before['label'], $finding['label']);

        $this->assertFalse(is_wp_error($check->unaccept($check->id())));
        $this->assertEquals(Finding::SEVERITY_FIX, $this->only($check->run())['severity']);

        remove_all_filters('pre_http_request');
    }

    /**
     * Handed over as text means nothing ran, which is the outcome we want - even though the
     * request succeeded and returned the file.
     */
    public function test_a_folder_that_serves_php_as_text_passes()
    {
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 200], 'body' => '<?php echo "FLS-EXECUTED"; // FLS-SOURCE'];
        });

        $finding = $this->only((new UploadsExecutionCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);

        remove_all_filters('pre_http_request');
    }

    public function test_a_refused_request_passes()
    {
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 403], 'body' => 'Forbidden'];
        });

        $this->assertEquals(
            Finding::STATE_PASSED,
            $this->only((new UploadsExecutionCheck())->run())['state']
        );

        remove_all_filters('pre_http_request');
    }

    /**
     * A response we cannot read is not a verdict either way.
     */
    public function test_an_unrecognised_response_is_not_read_as_a_verdict()
    {
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 200], 'body' => 'redirected to a login page'];
        });

        $finding = $this->only((new UploadsExecutionCheck())->run());

        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertFalse($finding['scored']);

        remove_all_filters('pre_http_request');
    }

    public function test_the_probe_leaves_nothing_behind()
    {
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 200], 'body' => 'FLS-EXECUTED'];
        });

        (new UploadsExecutionCheck())->run();

        $uploads = wp_upload_dir();

        $this->assertEmpty(glob(trailingslashit($uploads['basedir']) . 'fluentauth-check-*.php'));

        remove_all_filters('pre_http_request');
    }

    /* ------------------------------------------------------------- the whole */

    public function test_the_registry_runs_the_file_checks_alongside_the_settings_ones()
    {
        $this->writeMuPlugin('one', '<?php // something');

        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 403], 'body' => ''];
        });

        $summary = Registry::summary();
        $groups = array_column($summary['findings'], 'group');

        $this->assertContains('files', $groups);

        remove_all_filters('pre_http_request');
    }
}
