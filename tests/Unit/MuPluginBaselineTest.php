<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SecurityScanController;
use FluentAuth\App\Services\Checks\AcceptedFiles;
use FluentAuth\App\Services\Checks\Files\MuPluginsCheck;

/**
 * Recording the must-use plugins directory on purpose.
 *
 * The check records this folder silently on its first run, because a plugin that opened by
 * accusing somebody of their host's own files would be wrong on most sites. That takes the day
 * this plugin was installed on trust - so a site already broken into records the backdoor as
 * normal, and nothing automatic can fix that. The button can: somebody who has now read these
 * files says so, and the watching starts from a state a person actually looked at.
 *
 * What is pinned here is that it records, that it keeps watching afterwards, and that it does
 * not leave a promise standing over a file that is no longer there.
 */
class MuPluginBaselineTest extends BaseTestCase
{
    private $muDir;

    public function setUp(): void
    {
        parent::setUp();

        $this->muDir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        if (!is_dir($this->muDir)) {
            mkdir($this->muDir, 0755, true);
        }

        $this->cleanUp();

        delete_option('__fls_integrity_ignore_lists');
    }

    public function tearDown(): void
    {
        $this->cleanUp();

        delete_option('__fls_integrity_ignore_lists');

        parent::tearDown();
    }

    private function cleanUp()
    {
        array_map('unlink', glob($this->muDir . '/fls-baseline-test*') ?: []);
    }

    private function write($name, $contents)
    {
        file_put_contents($this->muDir . '/fls-baseline-test-' . $name, $contents);
    }

    private function remove($name)
    {
        @unlink($this->muDir . '/fls-baseline-test-' . $name);
    }

    /**
     * @return array|\WP_Error
     */
    private function record()
    {
        return SecurityScanController::baselineMuPlugins(new \WP_REST_Request());
    }

    /**
     * @return array
     */
    private function listing()
    {
        return SecurityScanController::getMuPlugins(new \WP_REST_Request());
    }

    /**
     * @param array $payload
     * @param string $name
     * @return string
     */
    private function statusOf($payload, $name)
    {
        foreach ($payload['files'] as $file) {
            if (strpos($file['name'], 'fls-baseline-test-' . $name) !== false) {
                return $file['status'];
            }
        }

        return 'absent';
    }

    public function test_recording_vouches_for_everything_in_the_folder()
    {
        $this->write('one.php', '<?php // one');
        $this->write('two.php', '<?php // two');

        $payload = $this->record();

        $this->assertFalse(is_wp_error($payload));
        $this->assertNotEmpty($payload['baselined_at']);
        $this->assertEquals(0, $payload['unrecorded']);
        $this->assertEquals('recorded', $this->statusOf($payload, 'one.php'));
        $this->assertEquals('recorded', $this->statusOf($payload, 'two.php'));
    }

    /**
     * Recording is not silencing. The whole reason accepting stores a hash rather than a path
     * is that a backdoor replacing a file somebody vouched for is the case this exists to catch.
     */
    public function test_a_file_that_changes_after_recording_is_reported_again()
    {
        $this->write('one.php', '<?php // one');
        $this->record();

        $this->write('one.php', '<?php // something else entirely');

        $payload = $this->listing();

        $this->assertEquals('changed', $this->statusOf($payload, 'one.php'));
        $this->assertEquals(1, $payload['unrecorded']);
    }

    public function test_a_file_that_arrives_after_recording_is_reported()
    {
        $this->write('one.php', '<?php // one');
        $this->record();

        $this->write('planted.php', '<?php // not mine');

        $payload = $this->listing();

        $this->assertEquals('new', $this->statusOf($payload, 'planted.php'));
        $this->assertEquals('recorded', $this->statusOf($payload, 'one.php'));
    }

    /**
     * Re-recording clears what it replaces.
     *
     * A hash left standing for a path that no longer exists is a promise an attacker can put a
     * file back underneath - the folder empties, the record does not, and the replacement reads
     * as expected. So the record is dropped for anything gone before the new one is written.
     */
    public function test_re_recording_forgets_a_file_that_is_no_longer_there()
    {
        $this->write('one.php', '<?php // one');
        $this->write('temporary.php', '<?php // for now');
        $this->record();

        $gone = AcceptedFiles::toRelative($this->muDir . '/fls-baseline-test-temporary.php');
        $this->assertArrayHasKey($gone, AcceptedFiles::all());

        $this->remove('temporary.php');
        $this->record();

        $this->assertArrayNotHasKey($gone, AcceptedFiles::all());
    }

    /**
     * The check and the button have to agree about which files are there, or the screen and the
     * finding are two answers to one question and one of them is wrong.
     */
    public function test_recording_settles_what_the_check_was_reporting()
    {
        $this->write('one.php', '<?php // one');

        /* First run records silently, so there is a baseline for the next file to be new against. */
        (new MuPluginsCheck())->run();

        $this->write('planted.php', '<?php // not mine');

        $findings = (new MuPluginsCheck())->run();
        $this->assertEquals('open', $findings[0]->toArray()['state']);

        $this->record();

        $findings = (new MuPluginsCheck())->run();
        $this->assertEquals('passed', $findings[0]->toArray()['state']);
    }

    public function test_an_empty_folder_has_nothing_to_record()
    {
        if (MuPluginsCheck::phpFiles()) {
            $this->markTestSkipped('This install has must-use plugins of its own.');
        }

        $this->assertWpErrorWithCode($this->record(), 'nothing_to_record');
    }
}
