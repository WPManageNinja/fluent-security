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

    /* ----------------------------------------------------- the per-unit ceiling */

    /**
     * The cap counts what it will not hash.
     *
     * A monitor that quietly watches less than it claims to is worse than one that watches
     * nothing, because the reader cannot tell which they have. So the walk carries on past the
     * ceiling to count, and the count is what the screens report.
     */
    public function test_a_unit_over_the_ceiling_reports_what_it_could_not_reach()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        $walk = BaselineTargets::hashUnit($this->unitPath);

        $this->assertCount(4, $walk['hashes']);
        $this->assertEquals(9, $walk['total']);
        $this->assertEquals(5, $walk['skipped']);

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * The day a plugin grows past the ceiling, it must not report every file the walk no longer
     * reaches as deleted. That is thousands of findings from an ordinary Tuesday, and it is
     * indistinguishable from the event this whole feature exists to report.
     */
    public function test_growing_past_the_ceiling_is_not_reported_as_a_mass_deletion()
    {
        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();

        /* Nothing on disk changes - only how much of it can be watched. */
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
        BaselineScanner::compare();

        $this->assertEquals(Finding::STATE_PASSED, $this->onlyFinding()['state']);
        $this->assertEmpty(BaselineStore::changed());

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * The window has to be the same window next time, or a truncated unit reports a churn of
     * added and removed files on every scan without anything having happened.
     */
    public function test_the_watched_window_is_stable_across_runs()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        $first = array_keys(BaselineTargets::hashUnit($this->unitPath)['hashes']);
        $second = array_keys(BaselineTargets::hashUnit($this->unitPath)['hashes']);

        $this->assertEquals($first, $second);
        $this->assertEquals(['file-0.php', 'file-1.php', 'file-2.php', 'file-3.php'], $first);

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * Inside the window it still works. Truncation is a limit on reach, not an excuse to stop
     * reporting - a backdoored file within the watched set is exactly the case this must catch.
     */
    public function test_a_change_inside_the_window_is_still_reported()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();

        $this->writeUnitFile('file-1.php', '<?php // backdoored');
        BaselineScanner::compare();

        $finding = $this->onlyFinding();

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertStringContainsString('file-1.php', implode(' ', $finding['details']));

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * And a genuine deletion inside the window is still a deletion - the boundary suppresses
     * what was never looked at, not what was.
     */
    public function test_a_deletion_inside_the_window_is_still_reported()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();

        unlink($this->unitPath . '/file-1.php');
        BaselineScanner::compare();

        $finding = $this->onlyFinding();

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertStringContainsString('file-1.php', implode(' ', $finding['details']));

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    public function test_the_snapshot_records_that_a_unit_is_only_partly_watched()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();

        $summary = BaselineScanner::summary();

        $this->assertEquals(4, $summary['files']);
        $this->assertEquals(5, $summary['skipped']);
        $this->assertEquals(1, $summary['partial_units']);

        $units = array_column(BaselineScanner::units(), null, 'scope');

        $this->assertEquals(5, $units[$this->unitScope()]['skipped']);

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * A pass may not say "nothing has changed" over files nobody hashed. That sentence is a
     * claim about everything, so it is only available when everything was looked at.
     */
    public function test_a_clean_result_admits_what_it_did_not_look_at()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();
        BaselineScanner::compare();

        $finding = $this->onlyFinding();

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
        $this->assertStringNotContainsString('Nothing has changed since your snapshot', $finding['title']);
        $this->assertStringContainsString('5', $finding['title']);

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * A unit that grows past the ceiling has to start saying so, and one that shrinks back
     * under it has to stop - a stale warning about coverage is its own kind of wrong.
     */
    public function test_the_warning_appears_and_clears_as_the_unit_grows_and_shrinks()
    {
        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();
        $this->assertEquals(0, BaselineScanner::summary()['skipped']);

        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
        BaselineScanner::compare();

        $this->assertEquals(5, BaselineScanner::summary()['skipped']);

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
        BaselineScanner::compare();

        $this->assertEquals(0, BaselineScanner::summary()['skipped']);
        $this->assertEmpty(BaselineStore::partials());
    }

    public function test_clearing_the_snapshot_forgets_the_coverage_warning_too()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        for ($i = 0; $i < 9; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();
        $this->assertNotEmpty(BaselineStore::partials());

        BaselineStore::clear();

        $this->assertEmpty(BaselineStore::partials());

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    public function test_an_uninstalled_plugin_takes_its_coverage_warning_with_it()
    {
        add_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);

        $second = $this->addUnit('huge-plugin');

        for ($i = 0; $i < 9; $i++) {
            file_put_contents($second . '/file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::snapshot();
        $this->assertArrayHasKey('plugin:huge-plugin/huge-plugin.php', BaselineStore::partials());

        $this->removeUnit($second);
        BaselineScanner::compare();

        $this->assertArrayNotHasKey('plugin:huge-plugin/huge-plugin.php', BaselineStore::partials());

        remove_filter('fluent_auth/baseline_max_files', [$this, 'tinyCeiling']);
    }

    /**
     * @return int
     */
    public function tinyCeiling()
    {
        return 4;
    }

    /* ------------------------------------------------- what the screens are told */

    /**
     * Driven from what is installed, not from what is stored.
     *
     * A plugin installed since the snapshot has to appear saying so. A list that quietly
     * omitted the one extension nobody has a record of would be the opposite of useful.
     */
    public function test_the_unit_list_names_what_is_not_recorded()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $this->addUnit('installed-later');

        $units = BaselineScanner::units();
        $byScope = array_column($units, null, 'scope');

        $this->assertCount(2, $units);
        $this->assertTrue($byScope[$this->unitScope()]['in_snapshot']);
        $this->assertEquals(1, $byScope[$this->unitScope()]['file_count']);

        $later = $byScope['plugin:installed-later/installed-later.php'];

        $this->assertFalse($later['in_snapshot']);
        $this->assertEquals('none', $later['status']);
        $this->assertEquals(0, $later['changed']);
    }

    public function test_the_unit_list_carries_the_changed_files()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        BaselineScanner::snapshot();

        $this->writeUnitFile('script.php', '<?php // edited');
        $this->writeUnitFile('extra.php', '<?php // arrived');
        BaselineScanner::compare();

        $units = array_column(BaselineScanner::units(), null, 'scope');
        $unit = $units[$this->unitScope()];

        $this->assertEquals('changed', $unit['status']);
        $this->assertEquals(2, $unit['changed']);

        $paths = array_column($unit['changes'], 'status', 'path');

        $this->assertEquals('modified', $paths['script.php']);
        $this->assertEquals('added', $paths['extra.php']);
    }

    /**
     * The count past the cap survives even though the paths do not, so a row cannot report
     * two hundred changes when the folder holds five thousand.
     */
    public function test_a_truncated_change_list_still_counts_every_file()
    {
        BaselineScanner::snapshot();

        for ($i = 0; $i < 205; $i++) {
            $this->writeUnitFile('file-' . $i . '.php', '<?php // ' . $i);
        }

        BaselineScanner::compare();

        $units = array_column(BaselineScanner::units(), null, 'scope');

        $this->assertEquals(205, $units[$this->unitScope()]['changed']);
    }

    /* ------------------------------------------------------- one unit at a time */

    /**
     * Somebody who has reviewed one plugin should be able to vouch for that one without also
     * vouching for the eleven they have not looked at.
     */
    public function test_a_snapshot_can_be_taken_of_one_unit_alone()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        $second = $this->addUnit('other-plugin');
        file_put_contents($second . '/other.php', '<?php // other');

        $result = BaselineScanner::snapshot([$this->unitScope()]);

        $this->assertEquals(1, $result['taken']);
        $this->assertNotNull(BaselineStore::find($this->unitScope()));
        $this->assertNull(BaselineStore::find('plugin:other-plugin/other-plugin.php'));
    }

    public function test_accepting_one_unit_leaves_the_others_reporting()
    {
        $this->writeUnitFile('script.php', '<?php // code');
        $second = $this->addUnit('other-plugin');
        file_put_contents($second . '/other.php', '<?php // other');

        BaselineScanner::snapshot();

        $this->writeUnitFile('script.php', '<?php // edited');
        file_put_contents($second . '/other.php', '<?php // also edited');
        BaselineScanner::compare();

        $this->assertCount(2, BaselineStore::changed());

        BaselineScanner::snapshot([$this->unitScope()]);

        $changed = BaselineStore::changed();

        $this->assertCount(1, $changed);
        $this->assertEquals('plugin:other-plugin/other-plugin.php', $changed[0]->scope);
    }

    /**
     * A name that matches nothing records nothing, rather than quietly falling back to all of
     * them - which would turn a button on one row into a snapshot of the whole site.
     */
    public function test_an_unknown_scope_records_nothing()
    {
        $this->writeUnitFile('script.php', '<?php // code');

        $result = BaselineScanner::snapshot(['plugin:not-installed/not-installed.php']);

        $this->assertEquals(0, $result['taken']);
        $this->assertEmpty(BaselineStore::summaries());
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
