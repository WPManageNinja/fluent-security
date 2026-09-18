<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\ChecksumException;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;
use FluentAuth\App\Services\Recovery\FileRecovery;
use FluentAuth\App\Services\Recovery\RecoveryService;

/*
 * A core checker that already knows the answer, so no test asks api.wordpress.org.
 */
class StubCoreChecker extends CheckerService
{
    protected $answer;

    public function __construct(array $modifiedFiles)
    {
        $this->answer = $modifiedFiles;
        $this->ignoreLists = IntegrityHelper::getIgnoreLists();
    }

    public function getModifiedFiles()
    {
        return $this->answer;
    }

    public function getActiveModifiedFiles($grouped = false)
    {
        return $this->answer;
    }

    public function getModifiedFolders($isActive = false)
    {
        return [];
    }
}

/*
 * The service with its three seams under test control: the update offer, the upgrader, and
 * the checker. Everything else - the quarantine, the bookkeeping, the messages - is real.
 */
class TestableFileRecovery extends FileRecovery
{
    public static $offer = null;

    public static $coreResult = '6.9.4';

    public static $installResult = true;

    public static $installed = [];

    public static $checkers = [];

    public static function resetSeams()
    {
        self::$offer = null;
        self::$coreResult = '6.9.4';
        self::$installResult = true;
        self::$installed = [];
        self::$checkers = [];
    }

    protected static function coreOffer($fresh)
    {
        return self::$offer;
    }

    protected static function coreChecker()
    {
        if (!self::$checkers) {
            throw new \Exception('No checker');
        }

        $next = array_shift(self::$checkers);

        /*
         * A queued exception is thrown instead of returned, so a test can put the failure on
         * whichever of the two calls it means: the pre-flight fetch, or the re-check after the
         * files have already been moved.
         */
        if ($next instanceof \Exception) {
            throw $next;
        }

        return $next;
    }

    protected static function runCoreUpgrade($offer)
    {
        return self::$coreResult;
    }

    protected static function runExtensionInstall($type, $package)
    {
        self::$installed[] = [$type, $package];

        if (self::$installResult === 'real') {
            return parent::runExtensionInstall($type, $package);
        }

        return self::$installResult;
    }
}

/**
 * Putting files back.
 *
 * What is pinned here is mostly what must not happen: nothing is deleted, only the places
 * nothing legitimate lives in are swept, a reinstall that cannot proceed changes nothing,
 * and a request cannot name a folder the inventory does not know about.
 */
class FileRecoveryTest extends BaseTestCase
{
    protected $cleanup = [];

    public function setUp(): void
    {
        parent::setUp();

        foreach (['__fls_integrity_core_results', '__fls_integrity_extension_results', '__fls_integrity_ignore_lists', '__fls_integrity_settings', RecoveryService::LOG_OPTION] as $option) {
            delete_option($option);
        }

        /*
         * Seeded with one entry each, so the inventory reads them rather than asking
         * api.wordpress.org to fill them in - an empty transient is what makes it ask.
         */
        set_site_transient('update_plugins', (object)[
            'response'  => [],
            'no_update' => ['fls-seed/fls-seed.php' => (object)['id' => 'w.org/plugins/fls-seed', 'slug' => 'fls-seed']]
        ]);
        set_site_transient('update_themes', (object)['response' => [], 'no_update' => ['fls-seed' => []]]);

        wp_set_current_user($this->factory->user->create(['role' => 'administrator']));

        TestableFileRecovery::resetSeams();

        /* Nothing in these tests may reach the network. */
        add_filter('pre_http_request', [$this, 'answerHttp'], 10, 3);
    }

    public function tearDown(): void
    {
        remove_all_filters('pre_http_request');
        remove_all_filters('fluent_auth/integrity_plugin_targets');
        remove_all_filters('fluent_auth/integrity_theme_targets');
        remove_all_filters('upgrader_pre_download');
        remove_all_filters('plugins_api');

        foreach (array_reverse($this->cleanup) as $path) {
            $this->remove($path);
        }

        $this->remove(FileRecovery::quarantinePath());

        parent::tearDown();
    }

    /* Answers for the two things a reinstall may ask for; anything else fails loudly. */
    public $manifest = null;

    public function answerHttp($pre, $args, $url)
    {
        if (strpos($url, 'plugin-checksums/') !== false) {
            if ($this->manifest === null) {
                return ['response' => ['code' => 404], 'body' => ''];
            }

            return ['response' => ['code' => 200], 'body' => wp_json_encode(['files' => $this->manifest])];
        }

        /*
         * The upgrader's own after-care asks WordPress.org for updates. Answered with nothing
         * new, so the reinstall under test is the only thing that happens.
         */
        if (strpos($url, 'api.wordpress.org') !== false) {
            return [
                'response' => ['code' => 200],
                'body'     => wp_json_encode(['offers' => [], 'plugins' => [], 'themes' => [], 'no_update' => [], 'translations' => []])
            ];
        }

        return new \WP_Error('offline', 'Tests do not go online: ' . $url);
    }

    /* ------------------------------------------------------------ summary */

    public function test_summary_before_any_scan_says_so()
    {
        $summary = FileRecovery::summary();

        $this->assertFalse($summary['scanned']);
        $this->assertSame(0, $summary['core']['files']);
        $this->assertSame([], $summary['extensions']);
        $this->assertSame(0, $summary['quarantine']['files']);
    }

    public function test_summary_counts_core_findings_by_status_and_skips_accepted_ones()
    {
        update_option('__fls_integrity_core_results', [
            'files'      => [
                'wp-includes/a.php'       => ['status' => 'modified'],
                'wp-admin/x.php'          => ['status' => 'new'],
                'wp-includes/b.php'       => ['status' => 'deleted'],
                'favicon.ico'             => ['status' => 'new'],
                'wp-includes/ignored.php' => ['status' => 'modified']
            ],
            'folders'    => ['/extra'],
            'total'      => 5,
            'truncated'  => 0,
            'checked_at' => current_time('mysql')
        ], false);

        IntegrityHelper::updateIgnoreLists(['files' => ['/wp-includes/ignored.php'], 'folders' => []]);

        $summary = FileRecovery::summary();
        $core = $summary['core'];

        $this->assertTrue($summary['scanned']);
        $this->assertSame(4, $core['files']);
        $this->assertSame(1, $core['modified']);
        $this->assertSame(2, $core['new']);
        $this->assertSame(1, $core['deleted']);
        /* The favicon at the root is ordinary; the file in wp-admin is not. */
        $this->assertSame(1, $core['removable']);
        /* Changed, missing, and the wp-admin extra: what a reinstall would put right. */
        $this->assertSame(3, $core['fixable']);
        $this->assertSame(['/extra'], $core['folders']);
    }

    public function test_root_extras_alone_give_a_reinstall_nothing_to_do()
    {
        update_option('__fls_integrity_core_results', [
            'files'      => ['info.php' => ['status' => 'new'], 'laradumps.yaml' => ['status' => 'new']],
            'folders'    => [],
            'total'      => 2,
            'truncated'  => 0,
            'checked_at' => current_time('mysql')
        ], false);

        $core = FileRecovery::summary()['core'];

        $this->assertSame(2, $core['files']);
        $this->assertSame(0, $core['fixable']);
    }

    public function test_summary_lists_extensions_with_findings_and_says_why_some_cannot_be_reinstalled()
    {
        $this->fakeInventory([
            $this->target('fine', ['key' => 'fine/fine.php', 'name' => 'Fine']),
            $this->target('tampered', ['key' => 'tampered/tampered.php', 'name' => 'Tampered']),
            $this->target('renamed-folder', ['key' => 'renamed-folder/renamed.php', 'slug' => 'renamed', 'name' => 'Renamed']),
            $this->target('hello.php', ['key' => 'hello.php', 'slug' => 'hello-dolly', 'name' => 'Hello', 'single_file' => true]),
            $this->target('premium', ['key' => 'premium/premium.php', 'name' => 'Premium', 'verifiable' => false, 'reason' => 'not_on_wp_org']),
            $this->target('beta', ['key' => 'beta/beta.php', 'name' => 'Beta'])
        ]);

        IntegrityHelper::saveExtensionResults([
            'plugin:fine/fine.php'             => $this->result('fine', 'fine/fine.php', []),
            'plugin:tampered/tampered.php'     => $this->result('tampered', 'tampered/tampered.php', [
                'tampered.php' => ['status' => 'modified'],
                'shell.php'    => ['status' => 'new'],
                'ignored.php'  => ['status' => 'new']
            ]),
            'plugin:renamed-folder/renamed.php' => $this->result('renamed-folder', 'renamed-folder/renamed.php', ['renamed.php' => ['status' => 'modified']]),
            'plugin:hello.php'                 => $this->result('hello.php', 'hello.php', ['hello.php' => ['status' => 'modified']]),
            'plugin:beta/beta.php'             => array_merge($this->result('beta', 'beta/beta.php', []), ['verifiable' => false, 'reason' => 'version_not_published']),
            'plugin:gone/gone.php'             => $this->result('gone', 'gone/gone.php', ['gone.php' => ['status' => 'modified']])
        ]);

        IntegrityHelper::updateIgnoreLists(['files' => ['/wp-content/plugins/tampered/ignored.php'], 'folders' => []]);

        $rows = FileRecovery::summary()['extensions'];
        $byName = array_column($rows, null, 'name');

        $this->assertEqualsCanonicalizing(['Beta', 'Tampered', 'Renamed', 'Hello'], array_keys($byName), 'Clean, premium and uninstalled extensions have no row');

        /* The unpublished version sorts first: it is the loudest finding there is. */
        $this->assertSame('Beta', $rows[0]['name']);
        $this->assertTrue($rows[0]['suspicious']);
        $this->assertTrue($rows[0]['reinstallable']);

        $this->assertSame(2, $byName['Tampered']['files'], 'An accepted file is not counted');
        $this->assertSame(1, $byName['Tampered']['modified']);
        $this->assertSame(1, $byName['Tampered']['new']);
        $this->assertTrue($byName['Tampered']['reinstallable']);

        $this->assertFalse($byName['Renamed']['reinstallable']);
        $this->assertStringContainsString('renamed-folder', $byName['Renamed']['blocked']);

        $this->assertFalse($byName['Hello']['reinstallable']);
        $this->assertStringContainsString('single-file', $byName['Hello']['blocked']);
    }

    /* ------------------------------------------------------------ core */

    public function test_core_reinstall_refuses_when_the_current_release_is_not_on_offer()
    {
        TestableFileRecovery::$offer = null;

        $result = TestableFileRecovery::reinstallCore();

        $this->assertWpErrorWithCode($result, 'not_available');
        $this->assertStringContainsString('Update WordPress first', $result->get_error_message());
        $this->assertEmpty(get_option(RecoveryService::LOG_OPTION), 'Nothing happened, so nothing is logged');
    }

    public function test_core_reinstall_quarantines_extras_inside_core_directories_only()
    {
        TestableFileRecovery::$offer = (object)['response' => 'latest', 'current' => '6.9.4'];

        $planted = $this->plant(ABSPATH . 'wp-includes/fls-test-planted.php', '<?php // planted');
        $rootExtra = $this->plant(ABSPATH . 'fls-test-verification.html', 'google-site-verification');

        $findings = [
            'wp-includes/fls-test-planted.php' => ['status' => 'new'],
            'fls-test-verification.html'       => ['status' => 'new'],
            'wp-includes/version.php'          => ['status' => 'modified']
        ];

        /* Before: what the scan sees. After: the reinstall put version.php back. */
        TestableFileRecovery::$checkers = [
            new StubCoreChecker($findings),
            new StubCoreChecker(['fls-test-verification.html' => ['status' => 'new']])
        ];

        $result = TestableFileRecovery::reinstallCore();

        $this->assertIsArray($result, is_wp_error($result) ? $result->get_error_message() : '');
        $this->assertSame(['wp-includes/fls-test-planted.php'], $result['quarantined']);
        $this->assertSame([], $result['failed']);

        $this->assertFileDoesNotExist($planted, 'The planted file is out of wp-includes');
        $this->assertFileExists($rootExtra, 'A file at the root is left for a person to judge');

        $moved = $this->quarantined('wp-includes/fls-test-planted.php');
        $this->assertNotEmpty($moved, 'The planted file is kept, in quarantine');
        $this->assertStringEndsWith('.quarantined', $moved);
        $this->assertSame('<?php // planted', file_get_contents($moved));

        $manifest = json_decode(file_get_contents(dirname(dirname($moved)) . '/manifest.json'), true);
        $this->assertSame(['wp-includes/fls-test-planted.php'], $manifest['files']);

        $this->assertFileExists(FileRecovery::quarantinePath() . '/.htaccess');
        $this->assertFileExists(FileRecovery::quarantinePath() . '/index.php');

        /* The picture sent back is the one after the reinstall, and it is stored. */
        $this->assertSame(1, $result['remaining']);
        $this->assertSame(1, $result['files']['core']['files']);
        $this->assertSame(1, $result['files']['quarantine']['files']);
        $this->assertArrayHasKey('fls-test-verification.html', IntegrityHelper::getCoreResults()['files']);

        $history = RecoveryService::history();
        $this->assertSame('reinstall_core', $history[0]['action']);
    }

    /**
     * Checksums unavailable before anything is touched: refused, and nothing moved.
     *
     * The one path in this class that moves real files out of wp-includes, so the branch that
     * decides nothing has been changed is worth asserting rather than assuming. The exception's
     * own sentence is handed on, because it already names which of the two things went wrong.
     */
    public function test_core_reinstall_refuses_when_the_checksums_cannot_be_fetched()
    {
        TestableFileRecovery::$offer = (object)['response' => 'latest', 'current' => '6.9.4'];
        TestableFileRecovery::$checkers = [
            new ChecksumException(ChecksumException::UNREACHABLE, 'wordpress.org could not be reached.', 'Connection timed out')
        ];

        $result = TestableFileRecovery::reinstallCore();

        $this->assertWpErrorWithCode($result, 'checksums_unavailable');
        $this->assertSame('unreachable', $result->get_error_data()['reason']);

        // Nothing ran, so nothing was recorded and nothing was quarantined.
        $this->assertSame([], RecoveryService::history());
    }

    /**
     * Checksums that go away between the pre-flight and the re-check afterwards.
     *
     * The reinstall itself succeeded, so this is not a failure - but the verification did not
     * run, and the message must not say every core file now matches on the strength of a check
     * that never happened. See FileRecovery::rescanCore(), which returns null rather than 0
     * for exactly this.
     */
    public function test_core_reinstall_does_not_claim_a_verification_it_could_not_run()
    {
        TestableFileRecovery::$offer = (object)['response' => 'latest', 'current' => '6.9.4'];
        TestableFileRecovery::$checkers = [
            new StubCoreChecker([]),
            new ChecksumException(ChecksumException::UNREACHABLE, 'wordpress.org could not be reached.', 'Connection timed out')
        ];

        $result = TestableFileRecovery::reinstallCore();

        $this->assertNotWPError($result);
        $this->assertStringContainsString('could not be re-checked', $result['message']);
        $this->assertStringNotContainsString('every core file now matches', $result['message']);

        $history = RecoveryService::history();
        $this->assertStringContainsString('could not be re-checked', $history[0]['description']);
    }

    public function test_core_reinstall_says_so_when_wordpress_cannot_write_its_own_files()
    {
        TestableFileRecovery::$offer = (object)['response' => 'latest', 'current' => '6.9.4'];
        TestableFileRecovery::$checkers = [new StubCoreChecker([])];
        TestableFileRecovery::$coreResult = false;

        $result = TestableFileRecovery::reinstallCore();

        $this->assertWpErrorWithCode($result, 'not_writable');
    }

    public function test_core_reinstall_passes_on_the_upgraders_reason()
    {
        TestableFileRecovery::$offer = (object)['response' => 'latest', 'current' => '6.9.4'];
        TestableFileRecovery::$checkers = [new StubCoreChecker([])];
        TestableFileRecovery::$coreResult = new \WP_Error('download_failed', 'Package not available');

        $result = TestableFileRecovery::reinstallCore();

        $this->assertWpErrorWithCode($result, 'reinstall_failed');
        $this->assertStringContainsString('Package not available', $result->get_error_message());
    }

    /* ------------------------------------------------------------ extensions */

    public function test_extension_reinstall_refuses_what_the_inventory_does_not_know()
    {
        $this->fakeInventory([$this->target('demo', ['key' => 'demo/demo.php'])]);

        $result = TestableFileRecovery::reinstallExtension('plugin', '../../wp-config.php');

        $this->assertWpErrorWithCode($result, 'not_installed');
        $this->assertSame([], TestableFileRecovery::$installed);
    }

    public function test_extension_reinstall_refuses_what_has_no_official_copy()
    {
        $this->fakeInventory([$this->target('premium', ['key' => 'premium/premium.php', 'verifiable' => false, 'reason' => 'not_on_wp_org'])]);

        $result = TestableFileRecovery::reinstallExtension('plugin', 'premium/premium.php');

        $this->assertWpErrorWithCode($result, 'not_reinstallable');
        $this->assertSame([], TestableFileRecovery::$installed);
    }

    public function test_extension_reinstall_changes_nothing_when_the_check_itself_fails()
    {
        $dir = $this->makePlugin('fls-demo', ['fls-demo.php' => $this->header('Demo') . '// edited']);
        $this->fakeInventory([$this->target($dir, ['key' => 'fls-demo/fls-demo.php', 'slug' => 'fls-demo'])]);

        /* The checksum request fails outright rather than 404ing. */
        remove_all_filters('pre_http_request');
        add_filter('pre_http_request', function () {
            return new \WP_Error('http_request_failed', 'Timed out');
        });

        $result = TestableFileRecovery::reinstallExtension('plugin', 'fls-demo/fls-demo.php');

        $this->assertWpErrorWithCode($result, 'not_checked');
        $this->assertSame([], TestableFileRecovery::$installed);
        $this->assertFileExists($dir . '/fls-demo.php');
    }

    public function test_extension_reinstall_installs_the_same_version_from_the_directory()
    {
        $official = $this->header('Demo') . '// official';
        $dir = $this->makePlugin('fls-demo', [
            'fls-demo.php' => $this->header('Demo') . '// edited',
            'lib.php'      => '<?php // lib',
            'shell.php'    => '<?php // planted'
        ]);
        $this->manifest = [
            'fls-demo.php' => ['md5' => md5($official), 'sha256' => hash('sha256', $official)],
            'lib.php'      => ['md5' => md5('<?php // lib'), 'sha256' => hash('sha256', '<?php // lib')]
        ];
        $this->fakeInventory([$this->target($dir, ['key' => 'fls-demo/fls-demo.php', 'slug' => 'fls-demo'])]);

        $result = TestableFileRecovery::reinstallExtension('plugin', 'fls-demo/fls-demo.php');

        $this->assertIsArray($result, is_wp_error($result) ? $result->get_error_message() : '');
        $this->assertSame([['plugin', 'https://downloads.wordpress.org/plugin/fls-demo.1.0.0.zip']], TestableFileRecovery::$installed);

        /* The extra was moved before the upgrader was asked to clear the folder. */
        $this->assertSame(['wp-content/plugins/fls-demo/shell.php'], $result['quarantined']);
        $this->assertFileDoesNotExist($dir . '/shell.php');
        $this->assertNotEmpty($this->quarantined('wp-content/plugins/fls-demo/shell.php'));

        $this->assertSame('reinstall_plugin', RecoveryService::history()[0]['action']);
    }

    /*
     * The whole thing, with WordPress's own upgrader doing the copying from a zip built here.
     * This is the one test that proves a reinstall actually leaves the official files behind.
     */
    public function test_extension_reinstall_replaces_the_folder_with_the_official_copy()
    {
        $official = $this->header('Demo') . '// official';
        $dir = $this->makePlugin('fls-demo', [
            'fls-demo.php' => $this->header('Demo') . '// edited',
            'shell.php'    => '<?php // planted'
        ]);
        $this->manifest = [
            'fls-demo.php' => ['md5' => md5($official), 'sha256' => hash('sha256', $official)]
        ];
        $this->fakeInventory([$this->target($dir, ['key' => 'fls-demo/fls-demo.php', 'slug' => 'fls-demo'])]);

        $zip = $this->makeZip(['fls-demo/fls-demo.php' => $official]);

        add_filter('upgrader_pre_download', function () use ($zip) {
            return $zip;
        });

        TestableFileRecovery::$installResult = 'real';

        $result = TestableFileRecovery::reinstallExtension('plugin', 'fls-demo/fls-demo.php');

        $this->assertIsArray($result, is_wp_error($result) ? $result->get_error_message() : '');
        $this->assertSame($official, file_get_contents($dir . '/fls-demo.php'));
        $this->assertFileDoesNotExist($dir . '/shell.php');
        $this->assertSame(0, $result['remaining']);
        $this->assertStringContainsString('every file now matches', $result['message']);

        $stored = IntegrityHelper::getExtensionResults()['plugin:fls-demo/fls-demo.php'];
        $this->assertSame([], $stored['files'], 'The stored verdict is the one after the reinstall');
    }

    public function test_extension_on_an_unpublished_version_is_replaced_with_the_current_release()
    {
        $dir = $this->makePlugin('fls-demo', ['fls-demo.php' => $this->header('Demo', '9.9.9-beta')]);
        $this->manifest = null; // 404: no such version
        $this->fakeInventory([$this->target($dir, ['key' => 'fls-demo/fls-demo.php', 'slug' => 'fls-demo', 'version' => '9.9.9-beta'])]);

        add_filter('plugins_api', function () {
            return (object)['download_link' => 'https://downloads.wordpress.org/plugin/fls-demo.2.0.0.zip'];
        });

        $result = TestableFileRecovery::reinstallExtension('plugin', 'fls-demo/fls-demo.php');

        $this->assertIsArray($result, is_wp_error($result) ? $result->get_error_message() : '');
        $this->assertSame([['plugin', 'https://downloads.wordpress.org/plugin/fls-demo.2.0.0.zip']], TestableFileRecovery::$installed);
        $this->assertStringContainsString('replaced with the current WordPress.org release', $result['message']);
    }

    public function test_extension_reinstall_reports_what_was_moved_when_the_upgrader_cannot_write()
    {
        $official = $this->header('Demo') . '// official';
        $dir = $this->makePlugin('fls-demo', [
            'fls-demo.php' => $official,
            'shell.php'    => '<?php // planted'
        ]);
        $this->manifest = ['fls-demo.php' => ['md5' => md5($official), 'sha256' => hash('sha256', $official)]];
        $this->fakeInventory([$this->target($dir, ['key' => 'fls-demo/fls-demo.php', 'slug' => 'fls-demo'])]);

        TestableFileRecovery::$installResult = false;

        $result = TestableFileRecovery::reinstallExtension('plugin', 'fls-demo/fls-demo.php');

        $this->assertWpErrorWithCode($result, 'not_writable');
        $this->assertSame(['wp-content/plugins/fls-demo/shell.php'], $result->get_error_data()['quarantined']);
        $this->assertFileExists($dir . '/fls-demo.php', 'The official file is untouched');
    }

    /* ------------------------------------------------------------ helpers */

    protected function fakeInventory(array $targets)
    {
        add_filter('fluent_auth/integrity_plugin_targets', function () use ($targets) {
            return $targets;
        });

        add_filter('fluent_auth/integrity_theme_targets', function () {
            return [];
        });
    }

    protected function target($path, $overrides = [])
    {
        if (strpos($path, '/') !== 0) {
            $path = WP_PLUGIN_DIR . '/' . $path;
        }

        $slug = basename($path, '.php');

        return array_merge([
            'type'        => 'plugin',
            'key'         => $slug . '/' . $slug . '.php',
            'slug'        => $slug,
            'name'        => ucfirst($slug),
            'version'     => '1.0.0',
            'path'        => $path,
            'rel_path'    => 'wp-content/plugins/' . basename($path),
            'single_file' => false,
            'verifiable'  => true,
            'reason'      => ''
        ], $overrides);
    }

    protected function result($slug, $key, $files)
    {
        return [
            'type'        => 'plugin',
            'key'         => $key,
            'slug'        => $slug,
            'name'        => ucfirst(basename(dirname($key)) ?: $slug),
            'version'     => '1.0.0',
            'rel_path'    => 'wp-content/plugins/' . (strpos($key, '/') === false ? $key : dirname($key)),
            'verifiable'  => true,
            'reason'      => '',
            'files'       => $files,
            'total_files' => count($files),
            'truncated'   => 0,
            'checked_at'  => current_time('mysql')
        ];
    }

    protected function header($name, $version = '1.0.0')
    {
        return "<?php\n/*\nPlugin Name: {$name}\nVersion: {$version}\n*/\n";
    }

    protected function makePlugin($slug, array $files)
    {
        $dir = WP_PLUGIN_DIR . '/' . $slug;
        $this->remove($dir);
        $this->cleanup[] = $dir;

        foreach ($files as $relative => $contents) {
            wp_mkdir_p(dirname($dir . '/' . $relative));
            file_put_contents($dir . '/' . $relative, $contents);
        }

        return $dir;
    }

    protected function makeZip(array $entries)
    {
        $path = get_temp_dir() . 'fls-reinstall-' . wp_generate_password(8, false) . '.zip';
        $this->cleanup[] = $path;

        $zip = new \ZipArchive();
        $zip->open($path, \ZipArchive::CREATE);

        foreach ($entries as $name => $contents) {
            $zip->addFromString($name, $contents);
        }

        $zip->close();

        return $path;
    }

    protected function plant($path, $contents)
    {
        file_put_contents($path, $contents);
        $this->cleanup[] = $path;

        return $path;
    }

    /* The quarantined copy of a root-relative path, or '' if it is not there. */
    protected function quarantined($relative)
    {
        $root = FileRecovery::quarantinePath();

        if (!is_dir($root)) {
            return '';
        }

        $matches = glob($root . '/*/' . $relative . FileRecovery::QUARANTINE_SUFFIX);

        return $matches ? $matches[0] : '';
    }

    protected function remove($path)
    {
        if (is_file($path)) {
            @unlink($path);
            return;
        }

        if (!is_dir($path)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }

        @rmdir($path);
    }
}
