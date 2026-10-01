<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\CheckerService;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * The shape of what gets posted to the alerts relay.
 *
 * The relay reads `modified_folders` only when it is a JSON array, so anything that leaves a
 * hole in the PHP list silently empties that section of the alert - the count in the subject
 * line still comes out right, which is what makes it hard to spot.
 */
class ScanReportPayloadTest extends BaseTestCase
{
    private function checkerWithFolders($folders, $ignoredFolders)
    {
        $checker = (new \ReflectionClass(CheckerService::class))->newInstanceWithoutConstructor();

        $extraFolders = new \ReflectionProperty(CheckerService::class, 'extraFolders');
        $extraFolders->setAccessible(true);
        $extraFolders->setValue($checker, $folders);

        $ignoreLists = new \ReflectionProperty(CheckerService::class, 'ignoreLists');
        $ignoreLists->setAccessible(true);
        $ignoreLists->setValue($checker, ['files' => [], 'folders' => $ignoredFolders]);

        return $checker;
    }

    public function testFoldersSurviveAsAJsonArrayWhenOneHasBeenAccepted()
    {
        $checker = $this->checkerWithFolders(['/aaa', '/bbb', '/ccc'], ['/aaa']);

        $folders = $checker->getActiveModifiedFolders();

        $this->assertSame(['/bbb', '/ccc'], $folders);
        $this->assertSame('["\/bbb","\/ccc"]', json_encode($folders));
    }

    public function testTheFirstFolderBeingAcceptedIsTheCaseThatUsedToBreak()
    {
        // array_diff keeps keys, so dropping element 0 left {"1":...} - a JSON object.
        $checker = $this->checkerWithFolders(['/dropped', '/kept'], ['/dropped']);

        $encoded = json_encode(['modified_folders' => $checker->getActiveModifiedFolders()]);

        $this->assertSame('{"modified_folders":["\/kept"]}', $encoded);
    }

    public function testNothingAcceptedStillGivesAList()
    {
        $checker = $this->checkerWithFolders(['/aaa', '/bbb'], []);

        $this->assertSame('["\/aaa","\/bbb"]', json_encode($checker->getActiveModifiedFolders()));
    }

    /**
     * Both list-shaped keys, straight out of the builder the real send uses.
     *
     * A finding type that encodes as a JSON object is not read as "malformed" at the other end
     * - it is read as no findings of that type, which for a report holding only that type is
     * indistinguishable from a clean scan and raises no alert at all.
     */
    public function testTheListShapedKeysEncodeAsArrays()
    {
        $payload = IntegrityHelper::buildReportPayload(
            ['wp-load.php' => ['status' => 'modified', 'modified_at' => '']],
            [1 => '/kept', 2 => '/also-kept'],
            [3 => ['type' => 'plugin', 'name' => 'Acme', 'version' => '1.0', 'path' => '/x', 'reason' => 'Unpublished']]
        );

        $encoded = json_encode($payload);

        $this->assertStringContainsString('"modified_folders":["\/kept","\/also-kept"]', $encoded);
        $this->assertStringContainsString('"unpublished_versions":[{', $encoded);

        // The file list is keyed by path on purpose - that one is meant to be an object.
        $this->assertStringContainsString('"modified_files":{"wp-load.php"', $encoded);
    }

    public function testAnEmptyReportStillEncodesTheListKeysAsArrays()
    {
        $encoded = json_encode(IntegrityHelper::buildReportPayload([], [], []));

        $this->assertStringContainsString('"modified_folders":[]', $encoded);
        $this->assertStringContainsString('"unpublished_versions":[]', $encoded);
    }

    public function testEveryFolderAcceptedGivesAnEmptyArrayNotAnObject()
    {
        $checker = $this->checkerWithFolders(['/aaa'], ['/aaa']);

        $this->assertSame('[]', json_encode($checker->getActiveModifiedFolders()));
    }

    /*
     * The email and the findings list must say the same thing. Whatever the site has marked
     * as expected on the scan screen - a file, a folder, a whole plugin - stays out of the
     * report, read from the same stored scan the list reads.
     */
    public function testAReportLeavesOutEverythingTheSiteHasAccepted()
    {
        update_option('__fls_integrity_core_results', [
            'version'    => '6.9.4',
            'files'      => [
                'wp-includes/pluggable.php' => ['status' => 'modified', 'modified_at' => ''],
                'wp-includes/accepted.php'  => ['status' => 'modified', 'modified_at' => '']
            ],
            'folders'    => ['/old-site', '/accepted'],
            'truncated'  => 0,
            'checked_at' => current_time('mysql')
        ], false);

        IntegrityHelper::saveExtensionResults([
            'plugin:demo/demo.php'   => [
                'type' => 'plugin', 'key' => 'demo/demo.php', 'name' => 'Demo', 'version' => '1.0.0',
                'rel_path' => 'wp-content/plugins/demo', 'verifiable' => true, 'reason' => '',
                'files' => ['demo.php' => ['status' => 'modified'], 'ok.php' => ['status' => 'new']]
            ],
            'plugin:beta/beta.php'   => [
                'type' => 'plugin', 'key' => 'beta/beta.php', 'name' => 'Beta', 'version' => '2.0.0-rc1',
                'rel_path' => 'wp-content/plugins/beta', 'verifiable' => false,
                'reason' => 'version_not_published', 'files' => []
            ]
        ]);

        IntegrityHelper::updateIgnoreLists([
            'files'   => ['/wp-includes/accepted.php', '/wp-content/plugins/demo/ok.php'],
            'folders' => ['/accepted', '/wp-content/plugins/beta']
        ]);

        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'active', 'api_id' => 'site_x', 'api_key' => 'fask_x', 'auto_scan' => 'yes'
        ]));

        $sent = null;
        $capture = function ($preempt, $args, $url) use (&$sent) {
            if (strpos($url, '/reports') !== false) {
                $sent = $args['body'];
            }

            return ['response' => ['code' => 200, 'message' => ''], 'body' => json_encode(['status' => 'success']), 'headers' => []];
        };

        add_filter('pre_http_request', $capture, 10, 3);
        IntegrityHelper::sendStoredReport();
        remove_filter('pre_http_request', $capture, 10);

        $this->assertNotNull($sent);
        $payload = is_string($sent) ? json_decode($sent, true) : $sent;

        $this->assertSame(
            ['wp-includes/pluggable.php', 'wp-content/plugins/demo/demo.php'],
            array_keys($payload['modified_files'])
        );
        $this->assertSame(['/old-site'], $payload['modified_folders']);
        $this->assertSame([], $payload['unpublished_versions']);
    }
}
