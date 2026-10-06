<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SecurityScanController;

/**
 * Putting one core file back to what WordPress.org published.
 *
 * The only endpoint in the plugin that writes to a file somebody else's code will execute,
 * so most of what is pinned here is what it refuses to do: leave the directories it is
 * allowed in, touch a file it would not have shown you, act on a file with no original, or
 * report success for a write that did not happen.
 */
class RestoreFileTest extends BaseTestCase
{
    private $original = '<?php // the official contents' . "\n";

    private $file = 'fls-restore-test.php';

    public function setUp(): void
    {
        parent::setUp();

        /*
         * The official copy comes from an HTTP request; answered here so these tests describe
         * the writing rather than the fetching, and pass on a machine with no internet.
         */
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 200], 'body' => $this->original];
        });
    }

    public function tearDown(): void
    {
        remove_all_filters('pre_http_request');

        foreach ([ABSPATH . $this->file, ABSPATH . 'wp-admin/' . $this->file] as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }

        parent::tearDown();
    }

    /**
     * @param array $config
     * @return array|\WP_Error
     */
    private function restore($config)
    {
        $request = new \WP_REST_Request();
        $request->set_param('viewing_file', $config);

        return SecurityScanController::restoreFile($request);
    }

    private function writeAdminFile($contents)
    {
        $path = ABSPATH . 'wp-admin/' . $this->file;
        file_put_contents($path, $contents);

        return $path;
    }

    public function test_a_modified_file_is_put_back()
    {
        $path = $this->writeAdminFile('<?php // tampered with');

        $result = $this->restore([
            'file'   => $this->file,
            'folder' => 'wp-admin',
            'status' => 'modified'
        ]);

        $this->assertFalse(is_wp_error($result));
        $this->assertEquals($this->original, file_get_contents($path));
    }

    /**
     * A file the scan calls "new" has no original to go back to. Restoring it would mean
     * deleting it, which is a different decision with a different consequence, and it is not
     * going to be made by a button labelled the same as this one.
     */
    public function test_a_file_with_no_original_is_refused()
    {
        $path = $this->writeAdminFile('<?php // nobody knows where this came from');

        $result = $this->restore([
            'file'   => $this->file,
            'folder' => 'wp-admin',
            'status' => 'new'
        ]);

        $this->assertWpErrorWithCode($result, 'not_restorable');
        $this->assertStringContainsString('nobody knows', file_get_contents($path));
    }

    public function test_a_path_that_climbs_out_of_the_allowed_folders_is_refused()
    {
        $this->writeAdminFile('<?php // tampered with');

        $result = $this->restore([
            'file'   => '../wp-config.php',
            'folder' => 'wp-admin',
            'status' => 'modified'
        ]);

        $this->assertWPError($result);
    }

    public function test_an_unknown_folder_is_refused()
    {
        $this->assertWpErrorWithCode(
            $this->restore([
                'file'   => $this->file,
                'folder' => 'wp-content',
                'status' => 'modified'
            ]),
            'invalid_data'
        );
    }

    /**
     * The viewer will not show these, so the restore must not write them either - the two
     * resolve their paths through the same code precisely so this cannot come apart.
     */
    public function test_a_file_the_viewer_would_not_show_is_not_written_either()
    {
        $path = ABSPATH . 'wp-admin/fls-restore-test.env';
        file_put_contents($path, 'SECRET=1');

        $result = $this->restore([
            'file'   => 'fls-restore-test.env',
            'folder' => 'wp-admin',
            'status' => 'modified'
        ]);

        $this->assertWPError($result);
        $this->assertEquals('SECRET=1', file_get_contents($path));

        unlink($path);
    }

    public function test_a_missing_file_is_refused()
    {
        $this->assertWPError($this->restore([
            'file'   => 'this-file-does-not-exist.php',
            'folder' => 'wp-admin',
            'status' => 'modified'
        ]));
    }

    /**
     * Nothing is touched unless the official copy actually arrived. Emptying a core file
     * because wordpress.org was briefly unreachable would be a far worse outcome than
     * leaving it as it was.
     */
    public function test_nothing_is_written_when_the_official_copy_cannot_be_fetched()
    {
        remove_all_filters('pre_http_request');

        add_filter('pre_http_request', function () {
            return new \WP_Error('http_request_failed', 'Connection refused');
        });

        $path = $this->writeAdminFile('<?php // tampered with');

        $result = $this->restore([
            'file'   => $this->file,
            'folder' => 'wp-admin',
            'status' => 'modified'
        ]);

        $this->assertWpErrorWithCode($result, 'no_original');
        $this->assertStringContainsString('tampered with', file_get_contents($path));
    }

    public function test_a_request_with_no_file_is_refused()
    {
        $this->assertWpErrorWithCode($this->restore(['status' => 'modified']), 'invalid_data');
        $this->assertWpErrorWithCode($this->restore(['file' => $this->file]), 'invalid_data');
    }
}
