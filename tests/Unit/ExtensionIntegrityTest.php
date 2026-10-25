<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\ExtensionChecker;
use FluentAuth\App\Services\IntegrityChecker\ExtensionInventory;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/*
 * Plugin and theme integrity checking.
 *
 * Nothing here talks to wordpress.org. The comparison, the queue and the bookkeeping are the
 * parts with logic in them, and they are all reachable with a manifest built by hand and a
 * directory of files in the temp dir. The update transients are pre-seeded so the inventory
 * never triggers an update check of its own.
 */
class ExtensionIntegrityTest extends BaseTestCase
{
    protected $tempDirs = [];

    public function setUp(): void
    {
        parent::setUp();

        delete_option('__fls_integrity_extension_results');
        delete_option('__fls_integrity_ignore_lists');

        /*
         * An empty update transient means "WordPress has not asked wordpress.org yet", which
         * the inventory answers by asking. Seeded here so the tests stay offline.
         */
        set_site_transient('update_plugins', (object)['response' => [], 'no_update' => []]);
        set_site_transient('update_themes', (object)['response' => [], 'no_update' => []]);
    }

    public function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->deleteDir($dir);
        }

        $this->tempDirs = [];

        remove_all_filters('fluent_auth/integrity_plugin_targets');
        remove_all_filters('fluent_auth/integrity_theme_targets');

        parent::tearDown();
    }

    /* ------------------------------------------------------------ comparison */

    public function testReportsAddedModifiedAndDeletedFiles()
    {
        $dir = $this->makeExtensionDir([
            'unchanged.php'   => '<?php // same',
            'tampered.php'    => '<?php // local edit',
            'unexpected.php'  => '<?php // not shipped'
        ]);

        $manifest = [
            'algo'  => 'md5',
            'files' => [
                'unchanged.php' => [md5('<?php // same')],
                'tampered.php'  => [md5('<?php // as published')],
                'missing.php'   => [md5('<?php // shipped but gone')]
            ]
        ];

        $findings = $this->compare($this->target($dir), $manifest);

        $this->assertArrayNotHasKey('unchanged.php', $findings, 'A matching file is not a finding');
        $this->assertEquals('modified', $findings['tampered.php']['status']);
        $this->assertEquals('new', $findings['unexpected.php']['status']);
        $this->assertEquals('deleted', $findings['missing.php']['status']);
        $this->assertCount(3, $findings);
    }

    /*
     * A published file can have more than one acceptable hash - the same source with different
     * line endings being the usual reason - so the manifest gives a list and any member of it
     * counts as a match.
     */
    public function testAcceptsAnyOfSeveralPublishedHashes()
    {
        $dir = $this->makeExtensionDir(['readme.txt' => "line one\nline two"]);

        $findings = $this->compare($this->target($dir), [
            'algo'  => 'md5',
            'files' => [
                'readme.txt' => [md5("line one\r\nline two"), md5("line one\nline two")]
            ]
        ]);

        $this->assertSame([], $findings, 'The second acceptable hash should match');
    }

    public function testFindsChangesInNestedDirectories()
    {
        $dir = $this->makeExtensionDir([
            'includes/deep/nested.php' => '<?php // edited'
        ]);

        $findings = $this->compare($this->target($dir), [
            'algo'  => 'md5',
            'files' => ['includes/deep/nested.php' => [md5('<?php // original')]]
        ]);

        $this->assertEquals('modified', $findings['includes/deep/nested.php']['status']);
    }

    public function testIgnoresGeneratedAndVersionControlFiles()
    {
        $dir = $this->makeExtensionDir([
            '.DS_Store'          => 'junk',
            'error.log'          => 'noise',
            '.git/config'        => '[core]',
            'node_modules/a.js'  => 'var a;',
            'real.php'           => '<?php // edited'
        ]);

        $findings = $this->compare($this->target($dir), [
            'algo'  => 'md5',
            'files' => ['real.php' => [md5('<?php // original')]]
        ]);

        $this->assertEquals(['real.php'], array_keys($findings),
            'Only the real file should be reported; the rest are noise on every site');
    }

    /* node_modules is noise, but a PHP file in it runs, so it is not a hiding place. */
    public function testPhpInsideNodeModulesIsStillReported()
    {
        $dir = $this->makeExtensionDir([
            'node_modules/pkg/index.js'     => 'var a;',
            'node_modules/pkg/shell.php'    => '<?php // planted',
            'real.php'                      => '<?php // original'
        ]);

        $findings = $this->compare($this->target($dir), [
            'algo'  => 'md5',
            'files' => ['real.php' => [md5('<?php // original')]]
        ]);

        $this->assertEquals(['node_modules/pkg/shell.php'], array_keys($findings));
        $this->assertEquals('new', $findings['node_modules/pkg/shell.php']['status']);
    }

    /* A single-file plugin is its own whole extent, not the plugins directory it sits in. */
    public function testSingleFilePluginHashesOnlyItself()
    {
        $dir = $this->makeExtensionDir([
            'hello.php'    => '<?php // edited',
            'unrelated.php' => '<?php // another plugin entirely'
        ]);

        $target = $this->target($dir . '/hello.php');
        $target['single_file'] = true;

        $findings = $this->compare($target, [
            'algo'  => 'md5',
            'files' => ['hello.php' => [md5('<?php // original')]]
        ]);

        $this->assertEquals(['hello.php'], array_keys($findings),
            'A single-file plugin must not drag in its neighbours');
    }

    /* --------------------------------------------------------- ignore filtering */

    public function testIgnoredExtensionFilesDropOutOfTheActiveFindings()
    {
        IntegrityHelper::storeExtensionResult($this->result([
            'noisy.php'  => ['status' => 'modified', 'modified_at' => ''],
            'urgent.php' => ['status' => 'new', 'modified_at' => '']
        ]));

        $active = IntegrityHelper::getActiveExtensionFindings();
        $this->assertCount(2, $active);

        /* The browser stores ignores root-relative and with a leading slash. */
        IntegrityHelper::updateIgnoreLists([
            'files'   => ['/wp-content/plugins/demo/noisy.php'],
            'folders' => []
        ]);

        $active = IntegrityHelper::getActiveExtensionFindings();

        $this->assertEquals(['wp-content/plugins/demo/urgent.php'], array_keys($active));
    }

    public function testUnverifiableExtensionsContributeNoFindings()
    {
        IntegrityHelper::storeExtensionResult(array_merge($this->result([
            'whatever.php' => ['status' => 'modified', 'modified_at' => '']
        ]), ['verifiable' => false, 'reason' => 'not_on_wp_org']));

        $this->assertSame([], IntegrityHelper::getActiveExtensionFindings(),
            'Something that was never checked cannot have findings');
    }

    /* ------------------------------------------------------------- bookkeeping */

    public function testFindingsBeyondTheCapAreCountedButNotStored()
    {
        add_filter('fluent_auth/integrity_max_extension_findings', function () {
            return 5;
        });

        $files = [];
        for ($i = 0; $i < 12; $i++) {
            $files["file-$i.php"] = ['status' => 'new', 'modified_at' => ''];
        }

        $stored = IntegrityHelper::storeExtensionResult($this->result($files));

        $this->assertCount(5, $stored['files']);
        $this->assertEquals(12, $stored['total_files']);
        $this->assertEquals(7, $stored['truncated']);

        remove_all_filters('fluent_auth/integrity_max_extension_findings');
    }

    /*
     * A result key carries the plugin's own file name, so it contains dots. This is a guard
     * against reading these keys back with dot-notation lookup, which silently finds nothing
     * and made every scheduled run re-check the same handful of plugins for ever.
     */
    public function testResultsAreFoundAgainUnderKeysContainingDots()
    {
        $result = $this->result(['x.php' => ['status' => 'new', 'modified_at' => '']]);

        IntegrityHelper::storeExtensionResult($result);

        $key = IntegrityHelper::getResultKey($result);
        $stored = IntegrityHelper::getExtensionResults();

        $this->assertStringContainsString('.', $key);
        $this->assertArrayHasKey($key, $stored);
        $this->assertEquals('demo/demo.php', $stored[$key]['key']);
    }

    public function testSummaryCountsWhatCouldNotBeCheckedFromTheInventory()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'verifiable' => true]),
            $this->target('/tmp/b', ['key' => 'b/b.php', 'verifiable' => true]),
            $this->target('/tmp/c', ['key' => 'c/c.php', 'verifiable' => false, 'reason' => 'not_on_wp_org'])
        ]);

        /* Only one of the two checkable ones has actually been checked. */
        IntegrityHelper::storeExtensionResult($this->result(
            ['edited.php' => ['status' => 'modified', 'modified_at' => '']],
            ['key' => 'a/a.php']
        ));

        $summary = IntegrityHelper::getExtensionSummary();

        $this->assertEquals(3, $summary['total']);
        $this->assertEquals(2, $summary['verifiable']);
        $this->assertEquals(1, $summary['checked']);
        $this->assertEquals(1, $summary['unverifiable'], 'The premium one must still be counted');
        $this->assertEquals(1, $summary['with_issues']);
        $this->assertEquals(1, $summary['files']);
    }

    /*
     * The interactive scan never asks the server about the extensions it cannot check, so they
     * leave no stored result. The summary has to notice them anyway - otherwise reloading the
     * screen reports full coverage of a site that was only partly covered.
     */
    public function testUncheckableExtensionsAreCountedEvenWithNoStoredResult()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'verifiable' => true]),
            $this->target('/tmp/b', ['key' => 'b/b.php', 'verifiable' => false, 'reason' => 'not_on_wp_org']),
            $this->target('/tmp/c', ['key' => 'c/c.php', 'verifiable' => false, 'reason' => 'not_on_wp_org'])
        ]);

        $summary = IntegrityHelper::getExtensionSummary();

        $this->assertEquals(3, $summary['total']);
        $this->assertEquals(0, $summary['checked']);
        $this->assertEquals(2, $summary['unverifiable']);
    }

    /* ------------------------------------------------------------- the queue */

    /*
     * The scheduled scan works through the list across runs. This is the regression that
     * matters: with the queue ordering broken, every run scanned the same first few items and
     * a large site was never covered at all.
     */
    public function testScheduledScanWorksThroughEveryExtensionAcrossRuns()
    {
        $targets = [];
        for ($i = 0; $i < 4; $i++) {
            /* Unverifiable, so scanning one is instant and needs no network. */
            $targets[] = $this->target("/tmp/ext-$i", [
                'key'        => "ext-$i/ext-$i.php",
                'verifiable' => false,
                'reason'     => 'not_on_wp_org'
            ]);
        }

        $this->fakeInventory($targets);

        /* A zero budget stops after one item, so each call is one run of a busy site. */
        $covered = [];
        for ($run = 0; $run < 4; $run++) {
            IntegrityHelper::scanExtensionBatch(0);
            $covered[] = count(IntegrityHelper::getExtensionResults());
        }

        $this->assertEquals([1, 2, 3, 4], $covered,
            'Each run must reach an extension the previous runs had not');
    }

    public function testTheQueueRechecksTheOldestResultFirst()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'verifiable' => false, 'reason' => 'not_on_wp_org']),
            $this->target('/tmp/b', ['key' => 'b/b.php', 'verifiable' => false, 'reason' => 'not_on_wp_org'])
        ]);

        /* Both known, one checked longer ago than the other. */
        IntegrityHelper::saveExtensionResults([
            'plugin:a/a.php' => array_merge($this->result([], ['key' => 'a/a.php']), ['checked_at' => '2020-01-01 00:00:00']),
            'plugin:b/b.php' => array_merge($this->result([], ['key' => 'b/b.php']), ['checked_at' => '2030-01-01 00:00:00'])
        ]);

        IntegrityHelper::scanExtensionBatch(0);

        $results = IntegrityHelper::getExtensionResults();

        $this->assertNotEquals('2020-01-01 00:00:00', $results['plugin:a/a.php']['checked_at'],
            'The stalest result should have been the one refreshed');
        $this->assertEquals('2030-01-01 00:00:00', $results['plugin:b/b.php']['checked_at'],
            'The fresher one should have been left alone');
    }

    public function testResultsForUninstalledExtensionsAreForgotten()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'verifiable' => false, 'reason' => 'not_on_wp_org'])
        ]);

        IntegrityHelper::saveExtensionResults([
            'plugin:a/a.php'       => $this->result([], ['key' => 'a/a.php']),
            'plugin:gone/gone.php' => $this->result([], ['key' => 'gone/gone.php'])
        ]);

        IntegrityHelper::scanExtensionBatch(0);

        $this->assertArrayNotHasKey('plugin:gone/gone.php', IntegrityHelper::getExtensionResults(),
            'A deleted plugin should stop being reported');
    }

    /* --------------------------------------- an unpublished version is a finding */

    /*
     * "Could not verify" covers two unrelated situations and they must not be reported alike.
     * A premium plugin never had an official copy; a directory plugin on a version the directory
     * has never released had one and does not match it, which is what tampering looks like.
     */
    public function testOnlyExtensionsWithNoOfficialCopyCountAsBenign()
    {
        $this->assertEquals('benign', ExtensionInventory::getReasonSeverity('not_on_wp_org'));

        $this->assertEquals('suspicious', ExtensionInventory::getReasonSeverity('version_not_published'));
        $this->assertEquals('suspicious', ExtensionInventory::getReasonSeverity('no_manifest'));

        /* The check itself failing says nothing about the extension. */
        $this->assertEquals('unknown', ExtensionInventory::getReasonSeverity('download_failed'));
        $this->assertEquals('unknown', ExtensionInventory::getReasonSeverity('unreadable'));
        $this->assertEquals('unknown', ExtensionInventory::getReasonSeverity('no_version'));
    }

    public function testAnUnpublishedVersionIsReportedEvenThoughItHasNoChangedFiles()
    {
        IntegrityHelper::storeExtensionResult($this->unpublished());

        $suspicious = IntegrityHelper::getSuspiciousExtensions();

        $this->assertCount(1, $suspicious);
        $this->assertEquals('Demo', $suspicious[0]['name']);
        $this->assertEquals('/wp-content/plugins/demo', $suspicious[0]['path']);

        /* No file list, and still an outstanding problem. */
        $this->assertSame([], IntegrityHelper::getActiveExtensionFindings());
        $this->assertTrue(IntegrityHelper::hasExtensionIssues());
    }

    public function testAPremiumExtensionIsNotReportedAsAFinding()
    {
        IntegrityHelper::storeExtensionResult(array_merge($this->result([]), [
            'verifiable' => false,
            'reason'     => 'not_on_wp_org'
        ]));

        $this->assertSame([], IntegrityHelper::getSuspiciousExtensions());
        $this->assertFalse(IntegrityHelper::hasExtensionIssues(),
            'Having paid plugins installed is not a finding');
    }

    public function testAFailedCheckIsNotReportedAsAFinding()
    {
        IntegrityHelper::storeExtensionResult(array_merge($this->result([]), [
            'verifiable' => false,
            'reason'     => 'download_failed'
        ]));

        $this->assertSame([], IntegrityHelper::getSuspiciousExtensions());
        $this->assertFalse(IntegrityHelper::hasExtensionIssues());
    }

    /*
     * A pre-release build installed on purpose is indistinguishable from a tampered one, so the
     * row has to be dismissable - otherwise the site sits permanently red and the nightly email
     * cries wolf. Accepted as a directory, under the ignore list everything else already uses.
     */
    public function testAnUnpublishedVersionCanBeMarkedAsExpected()
    {
        IntegrityHelper::storeExtensionResult($this->unpublished());

        $this->assertTrue(IntegrityHelper::hasExtensionIssues());

        IntegrityHelper::updateIgnoreLists([
            'files'   => [],
            'folders' => ['/wp-content/plugins/demo']
        ]);

        $this->assertSame([], IntegrityHelper::getSuspiciousExtensions());
        $this->assertFalse(IntegrityHelper::hasExtensionIssues());
        $this->assertEquals(0, IntegrityHelper::getExtensionSummary()['suspicious']);
    }

    /* Accepting an extension accepts its changed files too, not only its version. */
    public function testMarkingAnExtensionExpectedAlsoAcceptsItsChangedFiles()
    {
        IntegrityHelper::storeExtensionResult($this->result([
            'tampered.php' => ['status' => 'modified', 'modified_at' => '']
        ]));

        $this->assertCount(1, IntegrityHelper::getActiveExtensionFindings());

        IntegrityHelper::updateIgnoreLists([
            'files'   => [],
            'folders' => ['/wp-content/plugins/demo']
        ]);

        $this->assertSame([], IntegrityHelper::getActiveExtensionFindings());
    }

    /*
     * The site's stored verdict is written by the core check alone, which knows nothing about
     * wp-content. Read back without this, the dashboard tile reports a healthy site over a scans
     * screen listing changed plugins.
     */
    public function testTheStoredVerdictIsCorrectedByWhatIsKnownAboutExtensions()
    {
        $settings = IntegrityHelper::getSettings();
        $settings['is_ok'] = 'yes';
        IntegrityHelper::saveSettings($settings);

        IntegrityHelper::storeExtensionResult($this->unpublished());

        $this->assertTrue(IntegrityHelper::hasExtensionIssues());
        $this->assertEquals('no', IntegrityHelper::getSettings()['is_ok'],
            'Storing a finding should turn the stored verdict off');
    }

    public function testSummaryCountsUnpublishedVersionsApartFromMissingCoverage()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'verifiable' => true, 'version' => '1.0.0']),
            $this->target('/tmp/b', ['key' => 'b/b.php', 'verifiable' => false, 'reason' => 'not_on_wp_org'])
        ]);

        IntegrityHelper::storeExtensionResult(array_merge(
            $this->result([], ['key' => 'a/a.php', 'version' => '1.0.0']),
            ['verifiable' => false, 'reason' => 'version_not_published']
        ));

        $summary = IntegrityHelper::getExtensionSummary();

        $this->assertEquals(2, $summary['unverifiable'], 'Neither could be checked');
        $this->assertEquals(1, $summary['suspicious'], 'Only one of them is a finding');
    }

    /* ------------------------------------------- the work list and the aside agree */

    /*
     * Whether wordpress.org publishes the exact version installed here is only discoverable by
     * asking. Once asked, the work list has to remember - otherwise it offers the plugin as
     * checkable while the aside counts it as unverified, and the screen contradicts itself.
     */
    public function testWorkListRemembersAVersionTheDirectoryDoesNotPublish()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'version' => '1.0.0'])
        ]);

        $this->assertTrue($this->firstTarget()['verifiable'], 'Nothing known about it yet');

        IntegrityHelper::storeExtensionResult(array_merge(
            $this->result([], ['key' => 'a/a.php', 'version' => '1.0.0']),
            ['verifiable' => false, 'reason' => 'version_not_published']
        ));

        $target = $this->firstTarget();

        $this->assertFalse($target['verifiable']);
        $this->assertEquals('version_not_published', $target['reason']);
        $this->assertEquals(
            IntegrityHelper::getExtensionSummary()['unverifiable'],
            count(array_filter($this->targets(), function ($t) { return !$t['verifiable']; })),
            'The work list and the aside must count the same blind spot'
        );
    }

    public function testAnUpdatedVersionEarnsAFreshAttempt()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'version' => '2.0.0'])
        ]);

        /* The failure was recorded against the version that used to be installed. */
        IntegrityHelper::storeExtensionResult(array_merge(
            $this->result([], ['key' => 'a/a.php', 'version' => '1.0.0']),
            ['verifiable' => false, 'reason' => 'version_not_published']
        ));

        $this->assertTrue($this->firstTarget()['verifiable'],
            'A newly installed version has not been ruled out');
    }

    /* The network being down once is no reason to stop trying. */
    public function testATransientDownloadFailureIsNotRememberedAsPermanent()
    {
        $this->fakeInventory([
            $this->target('/tmp/a', ['key' => 'a/a.php', 'version' => '1.0.0'])
        ]);

        IntegrityHelper::storeExtensionResult(array_merge(
            $this->result([], ['key' => 'a/a.php', 'version' => '1.0.0']),
            ['verifiable' => false, 'reason' => 'download_failed']
        ));

        $this->assertTrue($this->firstTarget()['verifiable']);
    }

    /* ------------------------------------------------------------- inventory */

    public function testRelativePathsAreTakenFromTheWordPressRoot()
    {
        $this->assertEquals(
            'wp-content/plugins/demo',
            ExtensionInventory::toRelativePath(ABSPATH . 'wp-content/plugins/demo')
        );
    }

    /* wp-content can be moved outside the root, where there is no relative form to give. */
    public function testPathsOutsideTheRootAreLeftAbsolute()
    {
        $this->assertEquals('/srv/shared/plugins/demo',
            ExtensionInventory::toRelativePath('/srv/shared/plugins/demo'));
    }

    public function testEveryReasonHasSomethingReadableToSay()
    {
        foreach (['not_on_wp_org', 'no_version', 'version_not_published', 'no_manifest', 'download_failed', 'unreadable'] as $reason) {
            $this->assertNotEmpty(ExtensionInventory::getReasonLabel($reason));
        }

        $this->assertNotEmpty(ExtensionInventory::getReasonLabel('something-new'));
    }

    /* ------------------------------------------------------- core file grouping */

    /*
     * Core findings are grouped by the place the scanner looked, which is the first segment of
     * the path. Grouping by the parent directory instead filed wp-admin/includes/file.php
     * under "wp-admin/includes", a group the screen does not render, so nested findings were
     * counted and then never shown.
     */
    public function testCoreFindingsGroupByTopLevelDirectory()
    {
        $service = (new \ReflectionClass(CheckerService::class))->newInstanceWithoutConstructor();

        $method = new \ReflectionMethod(CheckerService::class, 'groupFiles');
        $method->setAccessible(true);

        $grouped = $method->invoke($service, [
            'index.php'                   => ['status' => 'modified'],
            'wp-admin/admin.php'          => ['status' => 'modified'],
            'wp-admin/includes/file.php'  => ['status' => 'modified'],
            'wp-includes/js/deep/a.js'    => ['status' => 'new']
        ]);

        $this->assertEquals(['root', 'wp-admin', 'wp-includes'], array_keys($grouped));
        $this->assertEquals(['index.php'], array_keys($grouped['root']));
        $this->assertEquals(['admin.php', 'includes/file.php'], array_keys($grouped['wp-admin']));
        $this->assertEquals(['js/deep/a.js'], array_keys($grouped['wp-includes']));
    }

    /* ------------------------------------------------------------------ helpers */

    /* The work list exactly as the screen receives it. */
    protected function targets()
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));

        $request = new \WP_REST_Request('GET', '/fluent-auth/security-scan-settings/scan/targets');
        $data = rest_do_request($request)->get_data();

        return array_merge($data['plugins'], $data['themes']);
    }

    protected function firstTarget()
    {
        $targets = $this->targets();

        return reset($targets);
    }

    protected function compare($target, $manifest)
    {
        $method = new \ReflectionMethod(ExtensionChecker::class, 'compare');
        $method->setAccessible(true);

        return $method->invoke(new ExtensionChecker(), $target, $manifest);
    }

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
        return array_merge([
            'type'        => 'plugin',
            'key'         => 'demo/demo.php',
            'slug'        => 'demo',
            'name'        => 'Demo',
            'version'     => '1.0.0',
            'path'        => $path,
            'rel_path'    => 'wp-content/plugins/demo',
            'single_file' => false,
            'verifiable'  => true,
            'reason'      => ''
        ], $overrides);
    }

    /* A result for an extension the directory publishes, at a version it does not. */
    protected function unpublished($overrides = [])
    {
        return array_merge($this->result([], $overrides), [
            'verifiable' => false,
            'reason'     => 'version_not_published'
        ]);
    }

    protected function result($files, $overrides = [])
    {
        return array_merge($this->target(''), [
            'files'      => $files,
            'checked_at' => current_time('mysql')
        ], $overrides);
    }

    protected function makeExtensionDir(array $files)
    {
        $dir = get_temp_dir() . 'fls-ext-test-' . wp_generate_password(8, false);
        $this->tempDirs[] = $dir;

        foreach ($files as $relative => $contents) {
            $full = $dir . '/' . $relative;
            wp_mkdir_p(dirname($full));
            file_put_contents($full, $contents);
        }

        return $dir;
    }

    protected function deleteDir($dir)
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }

        @rmdir($dir);
    }
}
