<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Files\BackupFilesCheck;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\IntegrityChecker\RootExpectations;

/**
 * Kept copies in the web root, and the seam between the two surfaces that judge them.
 *
 * The integrity scan drops a kept copy on purpose - an `index.php~` is not a changed core
 * file, and reporting it there is noise nobody reads. That only holds while this check
 * picks the file up instead. The two lists had drifted apart, so a set of suffixes was
 * silenced by the scanner and unknown to the checklist, and a readable copy of wp-login.php
 * was reported by neither.
 *
 * So what is pinned here is the seam itself: every suffix the scan silences is a finding
 * here, asserted by walking the scanner's own list rather than by restating it.
 */
class BackupFilesCheckTest extends BaseTestCase
{
    /** @var string */
    private $root;

    /** @var array<int, string> */
    private $written = [];

    public function setUp(): void
    {
        parent::setUp();

        $this->root = untrailingslashit(ABSPATH);
        delete_option('__fls_dismissed_checks');
    }

    public function tearDown(): void
    {
        foreach ($this->written as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }

        $this->written = [];
        delete_option('__fls_dismissed_checks');

        parent::tearDown();
    }

    private function writeRootFile($name, $body = 'x')
    {
        $path = $this->root . '/' . $name;
        file_put_contents($path, $body);
        $this->written[] = $path;

        return $path;
    }

    /**
     * @return array<int, string>
     */
    private function reported()
    {
        $findings = (new BackupFilesCheck())->run();
        $details = [];

        foreach ($findings as $finding) {
            $array = $finding->toArray();

            if ($array['state'] === Finding::STATE_PASSED) {
                continue;
            }

            foreach ((array)$array['details'] as $line) {
                /* The line carries a size in brackets; the name is what matters here. */
                $details[] = trim(strtok($line, '('));
            }
        }

        return $details;
    }

    /**
     * The seam. Every suffix the scan silences has to be a finding here, or the file is
     * mentioned by nothing on the site.
     */
    public function testEverySuffixTheScanSilencesIsReportedHere()
    {
        foreach (RootExpectations::backupSuffixes() as $i => $suffix) {
            $name = 'fls-probe-' . $i . 'wp-login.php' . $suffix;

            /* `~` and the underscored forms attach directly; the dotted ones already do. */
            $this->writeRootFile($name);

            $this->assertTrue(
                RootExpectations::isNoise($name),
                sprintf('the scan is expected to silence %s', $name)
            );

            $this->assertContains(
                '/' . $name,
                $this->reported(),
                sprintf('%s is silenced by the scan, so this check must report it', $name)
            );
        }
    }

    public function testAKeptCopyOfTheRulesFileIsReportedHoweverItIsSpelt()
    {
        foreach (['.htaccess.bk', '.htaccess_old', '.htaccess-2024'] as $name) {
            $this->writeRootFile($name, 'deny from all');

            $this->assertContains('/' . $name, $this->reported(), $name);
        }
    }

    /**
     * The file the server actually protects stays unmentioned. WordPress rewrites it on
     * every permalink change, and a check that cried about it would be dismissed once and
     * then never read again.
     */
    public function testTheLiveRulesFileItselfIsNotAFinding()
    {
        $live = $this->root . '/.htaccess';
        $existed = file_exists($live);

        if (!$existed) {
            $this->writeRootFile('.htaccess', "# BEGIN WordPress\n# END WordPress\n");
        }

        $this->assertNotContains('/.htaccess', $this->reported());
    }

    public function testAnOrdinaryRootFileIsNotAFinding()
    {
        $this->writeRootFile('fls-probe-ordinary.php', '<?php // nothing to see');

        $this->assertNotContains('/fls-probe-ordinary.php', $this->reported());
    }

    public function testTheArchiveAndDumpNamesStillReport()
    {
        foreach (['fls-probe-site.zip', 'fls-probe-dump.sql', 'wp-config.php.txt'] as $name) {
            $this->writeRootFile($name);

            $this->assertContains('/' . $name, $this->reported(), $name);
        }
    }

    /**
     * The filter reaches both surfaces, which is the point of the list being shared. A
     * suffix added for a host's own convention has to be silenced by the scan and raised
     * here, not one or the other.
     */
    public function testTheFilterMovesBothSurfacesTogether()
    {
        $addSuffix = function ($suffixes) {
            $suffixes[] = '.keepme';

            return $suffixes;
        };

        add_filter('fluent_auth/scan_backup_suffixes', $addSuffix);

        $this->writeRootFile('fls-probe-thing.php.keepme');

        $this->assertTrue(RootExpectations::isNoise('fls-probe-thing.php.keepme'));
        $this->assertContains('/fls-probe-thing.php.keepme', $this->reported());

        remove_filter('fluent_auth/scan_backup_suffixes', $addSuffix);
    }

    public function testAnAcceptedFindingIsNotScored()
    {
        $this->writeRootFile('fls-probe-accepted.php.bk');

        Dismissals::add('backup_files');

        $findings = (new BackupFilesCheck())->run();
        $first = $findings[0]->toArray();

        $this->assertSame(Finding::STATE_ACCEPTED, $first['state']);
        $this->assertFalse($first['scored']);

        Dismissals::remove('backup_files');
    }
}
