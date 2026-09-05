<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\Checks\Files\IntegrityCheck;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * The scan's verdict, as a finding.
 *
 * What is pinned is when it speaks: never before a scan has run, quietly when the scan was
 * clean, and as the loudest row on the list when it was not - with the paths, and pointing
 * at the screen that can put them back.
 */
class IntegrityCheckTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        foreach (['__fls_integrity_core_results', '__fls_integrity_extension_results', '__fls_integrity_ignore_lists', '__fls_integrity_settings'] as $option) {
            delete_option($option);
        }
    }

    public function test_says_nothing_before_the_first_scan()
    {
        $this->assertSame([], (new IntegrityCheck())->run());
    }

    public function test_passes_when_the_last_scan_matched_everything()
    {
        update_option('__fls_integrity_core_results', $this->coreResults([]), false);

        $findings = (new IntegrityCheck())->run();

        $this->assertCount(1, $findings);
        $this->assertSame(Finding::STATE_PASSED, $findings[0]->state());
        $this->assertTrue($findings[0]->isScored());
    }

    public function test_reports_every_kind_of_difference_and_points_at_recovery()
    {
        update_option('__fls_integrity_core_results', $this->coreResults([
            'wp-includes/pluggable.php' => ['status' => 'modified'],
            'wp-admin/shell.php'        => ['status' => 'new'],
            'wp-includes/accepted.php'  => ['status' => 'modified']
        ]), false);

        IntegrityHelper::saveExtensionResults([
            'plugin:demo/demo.php' => [
                'type'        => 'plugin',
                'key'         => 'demo/demo.php',
                'slug'        => 'demo',
                'name'        => 'Demo',
                'version'     => '1.0.0',
                'rel_path'    => 'wp-content/plugins/demo',
                'verifiable'  => true,
                'reason'      => '',
                'files'       => ['demo.php' => ['status' => 'modified']],
                'total_files' => 1,
                'truncated'   => 0,
                'checked_at'  => current_time('mysql')
            ],
            'plugin:beta/beta.php' => [
                'type'       => 'plugin',
                'key'        => 'beta/beta.php',
                'slug'       => 'beta',
                'name'       => 'Beta',
                'version'    => '2.0.0-rc1',
                'rel_path'   => 'wp-content/plugins/beta',
                'verifiable' => false,
                'reason'     => 'version_not_published',
                'files'      => [],
                'checked_at' => current_time('mysql')
            ]
        ]);

        IntegrityHelper::updateIgnoreLists(['files' => ['/wp-includes/accepted.php'], 'folders' => []]);

        $findings = (new IntegrityCheck())->run();

        $this->assertCount(1, $findings);
        $finding = $findings[0];

        $this->assertSame(Finding::STATE_OPEN, $finding->state());
        $this->assertSame(Finding::SEVERITY_FIX, $finding->severity());
        $this->assertSame('files', $finding->get('group'));
        $this->assertSame('navigate', $finding->get('action'));
        $this->assertSame('security_recovery', $finding->get('route'));
        $this->assertSame('', $finding->get('dismiss'), 'Accepted one path at a time on the scan screen, not wholesale here');

        $this->assertStringStartsWith('3 files differ', $finding->get('title'), 'The accepted file is not counted');

        $details = $finding->get('details');
        $this->assertStringContainsString('Beta 2.0.0-rc1', $details[0], 'The unpublished version is listed first');
        $this->assertContains('WordPress — wp-includes/pluggable.php (changed)', $details);
        $this->assertContains('WordPress — wp-admin/shell.php (not in the official release)', $details);
        $this->assertContains('Demo — wp-content/plugins/demo/demo.php (changed)', $details);
        $this->assertNotContains('WordPress — wp-includes/accepted.php (changed)', $details);
    }

    public function test_counts_findings_past_the_storage_cap()
    {
        $results = $this->coreResults(['wp-includes/a.php' => ['status' => 'modified']]);
        $results['truncated'] = 400;
        update_option('__fls_integrity_core_results', $results, false);

        $finding = (new IntegrityCheck())->run()[0];

        $this->assertStringStartsWith('401 files differ', $finding->get('title'));
        $details = $finding->get('details');
        $this->assertStringContainsString('400 more files', end($details));
    }

    protected function coreResults($files)
    {
        return [
            'version'    => '6.9.4',
            'files'      => $files,
            'folders'    => [],
            'total'      => count($files),
            'truncated'  => 0,
            'checked_at' => current_time('mysql')
        ];
    }
}
