<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Files\ConfigPermissionsCheck;
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

    private function only($findings)
    {
        $this->assertCount(1, $findings);

        return $findings[0]->toArray();
    }

    /* ------------------------------------------------------------ mu-plugins */

    /**
     * The first sight of a file here is not evidence of anything. Hosts ship mu-plugins and
     * developers write them; opening with an alarm would be wrong on most sites on day one,
     * and being wrong once is how a security tool teaches people to ignore it.
     */
    public function test_files_never_seen_before_are_an_invitation_to_look_not_an_alarm()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $finding = $this->only((new MuPluginsCheck())->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertEquals('expected', $finding['dismiss']);
        $this->assertNotEmpty($finding['details']);

        /* One file is "a file", not "1 files". */
        $this->assertStringNotContainsString('1 files', $finding['title']);

        $this->writeMuPlugin('two', '<?php // and another');

        $this->assertStringContainsString('2 files', $this->only((new MuPluginsCheck())->run())['title']);
    }

    /**
     * Accepted, not passed. "There is nothing here" and "there are files here and you vouched
     * for them" are different facts, and the second is a decision worth keeping on the record
     * with a way back - it is still scored as resolved, because vouching for these is what
     * satisfying this check looks like.
     */
    public function test_accepting_them_settles_it_without_pretending_they_are_not_there()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $check = new MuPluginsCheck();
        $check->accept($check->id());

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_ACCEPTED, $finding['state']);
        $this->assertTrue($finding['scored']);
        $this->assertNotEmpty($finding['details']);
    }

    /**
     * An empty folder is the only thing that passes outright.
     */
    public function test_nothing_here_at_all_is_a_pass()
    {
        $finding = $this->only((new MuPluginsCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
    }

    public function test_an_acceptance_can_be_taken_back()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $check = new MuPluginsCheck();
        $check->accept($check->id());

        $this->assertFalse(is_wp_error($check->unaccept($check->id())));

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEmpty(AcceptedFiles::all());
    }

    /**
     * The claim this check can actually stand behind: not that a file is suspicious, but that
     * it is not the file you looked at.
     */
    public function test_a_file_that_changes_after_being_accepted_is_the_alarm()
    {
        $this->writeMuPlugin('one', '<?php // a perfectly ordinary mu-plugin');

        $check = new MuPluginsCheck();
        $check->accept($check->id());

        $this->writeMuPlugin('one', '<?php eval($_POST["x"]); // not that any more');

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
    }

    public function test_a_new_file_alongside_accepted_ones_is_reported()
    {
        $this->writeMuPlugin('one', '<?php // known');

        $check = new MuPluginsCheck();
        $check->accept($check->id());

        $this->writeMuPlugin('two', '<?php // brand new');

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertStringContainsString('fls-test-two.php', implode(' ', $finding['details']));
    }

    public function test_an_accepted_file_that_is_deleted_is_forgotten()
    {
        $this->writeMuPlugin('one', '<?php // known');

        $check = new MuPluginsCheck();
        $check->accept($check->id());

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

    /* ------------------------------------------------------- config file mode */

    /**
     * Pointed at a file of our own rather than the install's real wp-config.php - the test
     * suite has none at ABSPATH, and a check whose two outcomes are only ever skipped is a
     * check nobody has tested.
     *
     * @param int $mode
     * @return ConfigPermissionsCheck
     */
    private function configCheckOn($mode)
    {
        $path = $this->muDir . '/fls-test-config.php';
        file_put_contents($path, '<?php // stand-in for wp-config.php');
        chmod($path, $mode);
        clearstatcache(true, $path);

        return new TestableConfigPermissionsCheck($path);
    }

    public function test_a_world_readable_config_is_worth_a_look_and_never_scored_against_you()
    {
        $finding = $this->only($this->configCheckOn(0644)->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertFalse($finding['scored']);
    }

    /**
     * Group-readable is how a good many hosts let the web server and the site's own user share
     * the file. Marking that down would be marking a correct configuration down.
     */
    public function test_a_group_readable_config_is_not_reported()
    {
        $this->assertEquals(
            Finding::STATE_PASSED,
            $this->only($this->configCheckOn(0640)->run())['state']
        );
    }

    public function test_restricting_the_config_takes_read_access_away_from_others()
    {
        $check = $this->configCheckOn(0644);
        $result = $check->fix($check->id());

        $this->assertFalse(is_wp_error($result));
        $this->assertEquals(Finding::STATE_PASSED, $this->only($check->run())['state']);
    }

    /**
     * Every button a row draws has to do something. A dismissal declared without a handler
     * behind it reaches the reader as an error message from a button they were offered.
     */
    public function test_dismissing_it_takes_it_off_the_list_without_pretending_it_passed()
    {
        $check = $this->configCheckOn(0644);

        $this->assertFalse(is_wp_error($check->accept($check->id())));

        $finding = $this->only($check->run());

        $this->assertEquals(Finding::STATE_ACCEPTED, $finding['state']);
        $this->assertFalse($finding['scored']);
    }

    /**
     * A config file we cannot find is not a config file we have checked, and a pass would be
     * the assurance nobody verified.
     */
    public function test_a_config_file_that_cannot_be_found_reports_nothing_rather_than_passing()
    {
        $check = new TestableConfigPermissionsCheck('');

        $this->assertEmpty($check->run());
        $this->assertWpErrorWithCode($check->fix($check->id()), 'not_found');
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

/**
 * The permission check, pointed at a file we own. Everything below configPath() - the octal
 * test, the finding, the chmod and the re-read that follows it - is the real thing.
 */
class TestableConfigPermissionsCheck extends ConfigPermissionsCheck
{
    private $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    protected function configPath()
    {
        return $this->path;
    }
}
