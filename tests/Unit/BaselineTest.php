<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Baseline\BaselineScanner;
use FluentAuth\App\Services\Baseline\BaselineStore;
use FluentAuth\App\Services\Baseline\BaselineTargets;
use FluentAuth\App\Services\Checks\Files\BaselineCheck;
use FluentAuth\App\Services\Checks\Finding;

/**
 * The site's own record of its files.
 *
 * Most of what is pinned here is silence: the occasions this must say nothing are what decide
 * whether anybody still reads it in six months. A monitor that cries wolf on a media import or
 * a Tuesday's plugin updates has spent its only asset.
 */
class BaselineTest extends BaselineTestCase
{
    public function test_the_table_is_not_created_until_somebody_takes_a_snapshot()
    {
        $this->dropBaselineTable();

        $this->assertFalse(BaselineStore::hasTable());

        /* Reading is free, and creates nothing - most sites never open this feature. */
        BaselineScanner::summary();
        BaselineScanner::compare();
        (new BaselineCheck())->run();

        $this->assertFalse(BaselineStore::hasTable());

        BaselineScanner::snapshot();

        $this->assertTrue(BaselineStore::hasTable());
    }

    public function test_a_check_with_no_snapshot_says_nothing_at_all()
    {
        $this->dropBaselineTable();

        $this->assertEmpty((new BaselineCheck())->run());
    }

    /* ------------------------------------------------------------- what it covers */

    /**
     * Only files that can run. Snapshotting a media library means a bulk import reports two
     * thousand changed files, and one event like that teaches somebody to close the alert
     * without reading it for ever afterwards.
     */
    public function test_only_files_that_can_run_are_recorded()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        $this->writeUnitFile('app.js', 'console.log(1)');
        $this->writeUnitFile('photo.jpg', 'not really a photo');
        $this->writeUnitFile('styles.css', 'body{}');

        $hashes = BaselineTargets::hash($this->unitPath);

        $this->assertArrayHasKey('script.php', $hashes);
        $this->assertArrayHasKey('app.js', $hashes);
        $this->assertArrayNotHasKey('photo.jpg', $hashes);
        $this->assertArrayNotHasKey('styles.css', $hashes);
    }

    public function test_dotfiles_with_no_extension_are_still_recognised()
    {
        $this->writeUnitFile('.htaccess', 'Deny from all');

        $this->assertArrayHasKey('.htaccess', BaselineTargets::hash($this->unitPath));
    }

    /* ------------------------------------------------------------- what it reports */

    public function test_an_edited_file_is_reported()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $this->writeUnitFile('script.php', '<?php eval($_POST["x"]);');
        BaselineScanner::compare();

        $finding = $this->onlyFinding();

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('script.php', implode(' ', $finding['details']));
    }

    public function test_a_new_file_is_reported()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $this->writeUnitFile('backdoor.php', '<?php // hello');
        BaselineScanner::compare();

        $this->assertStringContainsString('backdoor.php', implode(' ', $this->onlyFinding()['details']));
    }

    public function test_a_deleted_file_is_reported()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        $this->writeUnitFile('other.php', '<?php // code');
        BaselineScanner::snapshot();

        unlink($this->unitPath . '/other.php');
        BaselineScanner::compare();

        $this->assertStringContainsString('other.php', implode(' ', $this->onlyFinding()['details']));
    }

    /* ------------------------------------------------------------- what it ignores */

    /**
     * The rule the whole feature stands on. Without it, the Tuesday somebody updates six
     * plugins produces hundreds of changed files that look exactly like a break-in.
     */
    public function test_a_version_bump_absorbs_its_own_changes_in_silence()
    {
        $this->writeUnitFile('script.php', '<?php // version one');
        BaselineScanner::snapshot();

        /* Everything changes, and the header says why. */
        $this->writeUnitFile('script.php', '<?php // version two, rewritten');
        $this->writeUnitFile('extra.php', '<?php // and a new file');
        $this->setUnitVersion('2.0.0');

        BaselineScanner::compare();

        $finding = $this->onlyFinding();

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
    }

    public function test_the_record_moves_on_after_an_update()
    {
        $this->writeUnitFile('script.php', '<?php // version one');
        BaselineScanner::snapshot();

        $this->writeUnitFile('script.php', '<?php // version two');
        $this->setUnitVersion('2.0.0');
        BaselineScanner::compare();

        /* And a change made after the update is caught against the new record. */
        $this->writeUnitFile('script.php', '<?php // tampered with');
        BaselineScanner::compare();

        $this->assertEquals(Finding::STATE_OPEN, $this->onlyFinding()['state']);
    }

    public function test_adding_media_is_never_a_change()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        for ($i = 0; $i < 20; $i++) {
            $this->writeUnitFile('image-' . $i . '.jpg', 'binary-ish');
        }

        BaselineScanner::compare();

        $this->assertEquals(Finding::STATE_PASSED, $this->onlyFinding()['state']);
    }

    /**
     * Somebody installing a plugin is an ordinary Tuesday. This feature's claim is about a
     * unit it already knows changing under it, not about what is installed at all.
     */
    public function test_a_plugin_installed_after_the_snapshot_is_recorded_not_reported()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $second = $this->addUnit('another-premium-plugin');
        BaselineScanner::compare();

        $this->assertEquals(Finding::STATE_PASSED, $this->onlyFinding()['state']);
        $this->assertNotNull(BaselineStore::find('plugin:' . basename($second) . '/' . basename($second) . '.php'));
    }

    /* ---------------------------------------------------------------- housekeeping */

    public function test_accepting_makes_the_current_files_the_new_normal()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $this->writeUnitFile('script.php', '<?php // changed on purpose');
        BaselineScanner::compare();

        $check = new BaselineCheck();
        $this->assertEquals(Finding::STATE_OPEN, $this->onlyFinding()['state']);

        $check->accept($check->id());

        $this->assertEquals(Finding::STATE_PASSED, $this->onlyFinding()['state']);

        /* And it goes on watching - accepting is not silencing. */
        $this->writeUnitFile('script.php', '<?php // changed again');
        BaselineScanner::compare();

        $this->assertEquals(Finding::STATE_OPEN, $this->onlyFinding()['state']);
    }

    public function test_an_uninstalled_plugin_is_forgotten()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        $second = $this->addUnit('temporary-plugin');
        BaselineScanner::snapshot();

        $this->assertCount(2, BaselineStore::summaries());

        $this->removeUnit($second);
        BaselineScanner::compare();

        $this->assertCount(1, BaselineStore::summaries());
    }

    public function test_a_hash_map_survives_being_stored_and_read_back()
    {
        for ($i = 0; $i < 200; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();

        $stored = BaselineStore::hashes($this->unitScope());

        $this->assertCount(200, $stored);
        $this->assertEquals(md5_file($this->unitPath . '/file-7.php'), $stored['file-7.php']);
    }

    public function test_the_summary_reports_what_it_covers()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $summary = BaselineScanner::summary();

        $this->assertTrue($summary['exists']);
        $this->assertEquals(1, $summary['units']);
        $this->assertEquals(1, $summary['files']);
        $this->assertNotEmpty($summary['taken_at']);
    }

    /**
     * @return array
     */
    private function onlyFinding()
    {
        $findings = (new BaselineCheck())->run();

        $this->assertCount(1, $findings);

        return $findings[0]->toArray();
    }
}
