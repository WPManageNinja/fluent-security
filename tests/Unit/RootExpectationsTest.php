<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\RootExpectations;

/**
 * What the root scan is allowed to stay quiet about.
 *
 * Two halves, and the second is the one worth guarding. Dropping `error_log` is a
 * convenience; not announcing `.well-known` while still searching it is the trade that makes
 * the first half safe. If the walk ever stops happening, the scan gets quieter and blinder at
 * the same time and nothing else in the suite would notice - so a planted shell is pinned
 * here twice: once that it is found, and once that it lands in a group the screen draws.
 */
class RootExpectationsTest extends BaseTestCase
{
    private $root;

    public function setUp(): void
    {
        parent::setUp();

        $this->root = trailingslashit(get_temp_dir()) . 'fls-root-expectations';
        $this->removeTree($this->root);
        wp_mkdir_p($this->root);
    }

    public function tearDown(): void
    {
        $this->removeTree($this->root);

        parent::tearDown();
    }

    private function removeTree($dir)
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (array_diff(scandir($dir), ['.', '..']) as $entry) {
            $path = $dir . '/' . $entry;
            is_dir($path) ? $this->removeTree($path) : @unlink($path);
        }

        @rmdir($dir);
    }

    private function write($relative, $contents = 'x')
    {
        $path = $this->root . '/' . ltrim($relative, '/');
        wp_mkdir_p(dirname($path));
        file_put_contents($path, $contents);

        return $path;
    }

    /* ------------------------------------------------------------------ files */

    /**
     * @dataProvider noisyNames
     */
    public function test_a_file_that_can_never_be_in_a_checksum_list_is_not_reported($name)
    {
        $this->assertTrue(RootExpectations::isNoise($name), $name . ' should be dropped.');
    }

    public function noisyNames()
    {
        return [
            ['error_log'],
            ['php_errorlog'],
            ['debug.log'],
            ['.htaccess'],
            ['.env'],
            ['.DS_Store'],
            ['.git'],
        ];
    }

    /**
     * The gap this closes: the same leftover file was reported or not on the strength of how
     * whoever made it chose to abbreviate "backup".
     *
     * @dataProvider keptCopies
     */
    public function test_a_kept_copy_is_dropped_however_it_was_spelt($name)
    {
        $this->assertTrue(RootExpectations::isNoise($name), $name . ' should be dropped.');
    }

    public function keptCopies()
    {
        return [
            ['.htaccess.bak'],
            ['.htaccess.bk'],
            ['.htaccess_old'],
            ['.htaccess-2024'],
            ['wp-config.php.save'],
            ['index.php.orig'],
            ['index.php~'],
            ['settings_bak'],
        ];
    }

    /**
     * The whole point of the list is that it is short. A scanner that says nothing about a
     * strangely named PHP file in the root is not a scanner.
     *
     * @dataProvider realFindings
     */
    public function test_an_unexpected_root_file_is_still_reported($name)
    {
        $this->assertFalse(RootExpectations::isNoise($name), $name . ' must still be reported.');
    }

    public function realFindings()
    {
        return [
            ['wp-lo4in.php'],
            ['shell.php'],
            ['index.php'],
            ['radio.php'],
            ['.user.ini'],
            ['wp-tmp.php'],
        ];
    }

    /**
     * `.user.ini` sets auto_prepend_file, which is a way to run code on every request. It
     * looks like the dotfiles either side of it on the list and belongs nowhere near them.
     */
    public function test_the_php_ini_override_is_not_treated_as_noise()
    {
        $this->assertFalse(RootExpectations::isNoise('.user.ini'));
    }

    /**
     * The report that prompted this: eighteen new files, seventeen of them furniture an SEO
     * plugin or a search console had written, and a readable `wp-config.php.bkk` in the
     * middle of them that nobody was going to read past the sitemaps.
     *
     * @dataProvider generatedNames
     */
    public function test_a_file_the_site_generated_about_itself_is_not_reported($name)
    {
        $this->assertTrue(RootExpectations::isNoise($name), $name . ' should be dropped.');
    }

    public function generatedNames()
    {
        return [
            ['sitemap.xml'],
            ['sitemap_index.xml'],
            ['post-sitemap.xml'],
            ['post_tag-sitemap.xml'],
            ['tribe_events_cat-sitemap.xml'],
            ['wp-sitemap.xml'],
            ['main-sitemap.xsl'],
            ['BingSiteAuth.xml'],
            ['googlecaf90c04662aac26.html'],
            ['locations.kml'],
            ['favicon.ico'],
            ['robots.txt'],
            ['ads.txt'],
            ['site.webmanifest'],
            ['browserconfig.xml'],
            ['apple-touch-icon-180x180.png'],
        ];
    }

    /**
     * The line the noise was burying. `.bkk` is not on the kept-copy list - which is what
     * keeps it visible here - and BackupFilesCheck reports it as well, because a readable
     * copy of wp-config is the database password served as plain text.
     *
     * @dataProvider notGenerated
     */
    public function test_what_only_looks_like_furniture_is_still_reported($name)
    {
        $this->assertFalse(RootExpectations::isNoise($name), $name . ' must still be reported.');
    }

    public function notGenerated()
    {
        return [
            ['wp-config.php.bkk'],
            /* An inert name with an extension that is not. */
            ['sitemap.php'],
            ['favicon.php'],
            /* A page somebody wrote, as against a console's fixed shape. */
            ['login.html'],
            ['index.html'],
            /* Host config that can carry auto_prepend_file. */
            ['php.ini'],
            ['.user.ini'],
            /* A plugin's own bootstrap is a PHP file in the root, and stays a finding. */
            ['aios-bootstrap.php'],
        ];
    }

    /**
     * A log lands wherever the code that errored was, so the core walk needs the same rule
     * the root has - `wp-admin/error_log` was reported on every scan of every site whose
     * host writes one, because the walk only ever excluded names ending in `.log`.
     */
    public function test_a_log_is_noise_in_a_core_directory_too()
    {
        foreach (['error_log', 'php_errorlog', 'debug.log', '.DS_Store'] as $name) {
            $this->assertTrue(RootExpectations::isSystemNoise($name), $name . ' should be dropped anywhere.');
        }
    }

    /**
     * The half that must not travel. A kept copy is silenced in the root only because
     * BackupFilesCheck reports it there instead, and that check looks at the root alone - so
     * carrying the suffixes into wp-admin would leave a readable copy of a core file
     * mentioned by neither.
     */
    public function test_a_kept_copy_in_a_core_directory_is_not_silenced_by_the_log_rule()
    {
        foreach (['wp-login.php.bak', 'index.php~', '.htaccess.bk'] as $name) {
            $this->assertFalse(RootExpectations::isSystemNoise($name), $name . ' must still be reported inside core.');
        }
    }

    /* ------------------------------------------------------------ directories */

    public function test_the_expected_directories_are_not_announced()
    {
        $this->assertTrue(RootExpectations::isExpectedDir('.well-known'));
        $this->assertTrue(RootExpectations::isExpectedDir('cgi-bin'));
    }

    /**
     * `.git` and `.idea` are directories, and they were silent before any of this existed.
     * The rule that drops them has to be asked before the file-or-directory question, or a
     * scan starts announcing every checkout and every editor folder as an unknown directory -
     * which is how this was caught.
     */
    public function test_a_tooling_directory_is_dropped_by_name_not_by_being_a_file()
    {
        foreach (['.git', '.idea', '.DS_Store'] as $name) {
            $this->assertTrue(RootExpectations::isNoise($name), $name . ' is a directory and must still be dropped.');
        }
    }

    public function test_an_unknown_directory_is_still_announced()
    {
        $this->assertFalse(RootExpectations::isExpectedDir('assets'));
        $this->assertFalse(RootExpectations::isExpectedDir('.git'));
    }

    /* ------------------------------------------------------------- the search */

    public function test_a_shell_planted_in_a_silenced_directory_is_found()
    {
        $this->write('.well-known/acme-challenge/shell.php', '<?php system($_GET["c"]);');

        $found = RootExpectations::executablesIn($this->root . '/.well-known', '.well-known');

        $this->assertArrayHasKey('.well-known/acme-challenge/shell.php', $found);
        $this->assertSame(32, strlen($found['.well-known/acme-challenge/shell.php']));
    }

    public function test_the_files_these_directories_exist_for_are_invisible()
    {
        $this->write('.well-known/acme-challenge/tokenvalue', 'token');
        $this->write('.well-known/apple-app-site-association', '{}');
        $this->write('.well-known/security.txt', 'Contact: x@example.com');

        $this->assertSame([], RootExpectations::executablesIn($this->root . '/.well-known', '.well-known'));
    }

    /**
     * Inside a directory nobody looks at, an .htaccess is not configuration - it is the thing
     * that decides what else in there is allowed to execute.
     */
    public function test_an_htaccess_inside_a_silenced_directory_is_reported()
    {
        $this->write('cgi-bin/.htaccess', "AddHandler application/x-httpd-php .txt\n");

        $found = RootExpectations::executablesIn($this->root . '/cgi-bin', 'cgi-bin');

        $this->assertArrayHasKey('cgi-bin/.htaccess', $found);
    }

    /**
     * And the other half of that: hosts ship an `.htaccess` in `cgi-bin` as a matter of
     * course, so hashing every one of them reported a file the host put there on every scan,
     * forever. What makes the file interesting is written in it.
     */
    public function test_an_htaccess_that_turns_nothing_on_is_not_reported()
    {
        $this->write('cgi-bin/.htaccess', "Options -Indexes\nDenyfrom all\n");

        $this->assertSame([], RootExpectations::executablesIn($this->root . '/cgi-bin', 'cgi-bin'));
    }

    /**
     * @dataProvider executingHtaccess
     */
    public function test_an_htaccess_that_can_run_code_is_reported($contents)
    {
        $this->write('cgi-bin/.htaccess', $contents);

        $found = RootExpectations::executablesIn($this->root . '/cgi-bin', 'cgi-bin');

        $this->assertArrayHasKey('cgi-bin/.htaccess', $found, $contents . ' switches execution on.');
    }

    public function executingHtaccess()
    {
        return [
            ["AddHandler application/x-httpd-php .txt\n"],
            ["SetHandler application/x-httpd-php\n"],
            ["php_value auto_prepend_file /tmp/x.php\n"],
            ["Options +ExecCGI\nAddHandler cgi-script .cgi\n"],
            ["Action php-cgi /cgi-bin/php\n"],
        ];
    }

    /**
     * @dataProvider runnableFiles
     */
    public function test_every_kind_of_runnable_file_is_found($name)
    {
        $this->write('cgi-bin/' . $name, 'payload');

        $found = RootExpectations::executablesIn($this->root . '/cgi-bin', 'cgi-bin');

        $this->assertArrayHasKey('cgi-bin/' . $name, $found, $name . ' can run and must be reported.');
    }

    public function runnableFiles()
    {
        return [['a.php'], ['a.phtml'], ['a.php5'], ['a.pht'], ['a.cgi'], ['a.pl'], ['a.py'], ['a.sh']];
    }

    public function test_a_missing_directory_is_not_an_error()
    {
        $this->assertSame([], RootExpectations::executablesIn($this->root . '/nope', 'nope'));
    }

    public function test_the_walk_is_capped_so_a_huge_directory_cannot_stall_a_scan()
    {
        for ($i = 0; $i < 12; $i++) {
            $this->write('cgi-bin/file' . $i . '.php', 'x');
        }

        $cap = function () {
            return 5;
        };

        add_filter('fluent_auth/scan_expected_dir_max_files', $cap);
        $found = RootExpectations::executablesIn($this->root . '/cgi-bin', 'cgi-bin');
        remove_filter('fluent_auth/scan_expected_dir_max_files', $cap);

        $this->assertLessThanOrEqual(5, count($found));
    }

    public function test_a_site_can_name_another_directory_as_expected()
    {
        $extra = function ($dirs) {
            $dirs[] = '.ci';

            return $dirs;
        };

        add_filter('fluent_auth/scan_expected_root_dirs', $extra);
        $expected = RootExpectations::isExpectedDir('.ci');
        remove_filter('fluent_auth/scan_expected_root_dirs', $extra);

        $this->assertTrue($expected);
    }

    /* ------------------------------------------------------------- the report */

    /**
     * The other half of finding it. The scan screen renders three groups and no others, so a
     * finding filed under `.well-known` would be counted in the total and then drawn nowhere -
     * which reads to whoever is looking as a scan that found nothing.
     */
    public function test_a_finding_under_a_silenced_directory_lands_where_the_screen_draws_it()
    {
        $grouped = CheckerService::groupFiles([
            '.well-known/acme-challenge/shell.php' => ['status' => 'new'],
            'cgi-bin/backdoor.cgi'                 => ['status' => 'new'],
            'wp-admin/includes/file.php'           => ['status' => 'modified'],
            'wp-includes/pluggable.php'            => ['status' => 'modified'],
            'wp-lo4in.php'                         => ['status' => 'new']
        ]);

        $this->assertSame(['root', 'wp-admin', 'wp-includes'], array_keys($grouped));

        /* The path is kept whole, so the row reads /.well-known/... like every other. */
        $this->assertArrayHasKey('.well-known/acme-challenge/shell.php', $grouped['root']);
        $this->assertArrayHasKey('cgi-bin/backdoor.cgi', $grouped['root']);
        $this->assertArrayHasKey('wp-lo4in.php', $grouped['root']);

        /* The two that are walked as folders keep their own groups, relative paths intact. */
        $this->assertArrayHasKey('includes/file.php', $grouped['wp-admin']);
        $this->assertArrayHasKey('pluggable.php', $grouped['wp-includes']);
    }
}
