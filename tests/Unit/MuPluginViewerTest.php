<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SecurityScanController;

/**
 * Reading one must-use plugin from the scan screen.
 *
 * The listing exists because nobody can tell a legitimate mu-plugin from a planted one without
 * opening it, and the check that watches these deliberately makes no accusation on its first
 * run. So the screen has to be able to show the source - which means an endpoint that takes a
 * filename from the browser and reads a file with it, and most of what is pinned here is what
 * that must refuse.
 */
class MuPluginViewerTest extends BaseTestCase
{
    private $muDir;

    public function setUp(): void
    {
        parent::setUp();

        $this->muDir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        if (!is_dir($this->muDir)) {
            mkdir($this->muDir, 0755, true);
        }

        file_put_contents($this->muDir . '/fls-view-test.php', '<?php // the one we mean');
    }

    public function tearDown(): void
    {
        array_map('unlink', glob($this->muDir . '/fls-view-test*') ?: []);

        parent::tearDown();
    }

    /**
     * @param array $config
     * @return array|\WP_Error
     */
    private function view($config)
    {
        $request = new \WP_REST_Request();
        $request->set_param('viewing_file', array_merge(['scope' => 'mu-plugin', 'status' => 'new'], $config));

        return SecurityScanController::viewFileDiff($request);
    }

    public function test_a_must_use_plugin_is_returned_as_source_with_nothing_to_compare()
    {
        $result = $this->view(['file' => 'fls-view-test.php']);

        $this->assertFalse(is_wp_error($result));
        $this->assertStringContainsString('the one we mean', $result['fileContent']);

        /*
         * No official copy of a file the host or a developer wrote, so there is never a diff -
         * and a viewer that offered one would be offering to restore a file to something that
         * was never its contents.
         */
        $this->assertFalse($result['hasDiff']);
        $this->assertEmpty($result['originalFileContent']);
    }

    /**
     * The name comes from the browser, so it is a path somebody can choose. Resolved through
     * realpath() against the directory rather than trusted, or this endpoint reads any file
     * the web server can.
     */
    public function test_a_name_that_walks_out_of_the_directory_is_refused()
    {
        foreach (['../../wp-config.php', '../../../etc/passwd', 'sub/../../wp-config.php'] as $escape) {
            $this->assertWpErrorWithCode($this->view(['file' => $escape]), 'invalid_data');
        }
    }

    /**
     * WordPress only loads .php from this folder, so nothing else in it is a must-use plugin -
     * and a viewer that read anything at all would turn a listing into a file browser.
     */
    public function test_only_php_is_readable_from_the_directory()
    {
        file_put_contents($this->muDir . '/fls-view-test.log', 'not a plugin');

        $this->assertWpErrorWithCode($this->view(['file' => 'fls-view-test.log']), 'invalid_data');
    }

    /**
     * A folder in here can legitimately hold a wp-config.php of somebody else's - the shared
     * refusal list is applied to these the same way it is to core files.
     */
    public function test_the_sensitive_name_list_still_applies()
    {
        file_put_contents($this->muDir . '/fls-view-test-wp-config.php', '<?php // secrets');

        $this->assertWpErrorWithCode($this->view(['file' => 'fls-view-test-wp-config.php']), 'invalid_data');
    }

    public function test_a_file_that_is_not_there_is_refused_rather_than_read_as_empty()
    {
        $this->assertWpErrorWithCode($this->view(['file' => 'fls-nothing-here.php']), 'invalid_data');
    }
}
