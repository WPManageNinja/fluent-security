<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\LogsController;

class LogsControllerTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}fls_auth_logs");

        /*
         * The query builder's paginate() reads the page and per-page straight out of the
         * request superglobals rather than from arguments, so a test has to put them there.
         */
        $_GET['page'] = 1;
        $_REQUEST['per_page'] = 20;
    }

    public function tearDown(): void
    {
        unset($_GET['page'], $_REQUEST['per_page']);

        parent::tearDown();
    }

    /**
     * @param array $overrides
     * @return void
     */
    private function log($overrides = [])
    {
        global $wpdb;

        $wpdb->insert($wpdb->prefix . 'fls_auth_logs', array_merge([
            'username'   => 'admin',
            'user_id'    => null,
            'agent'      => 'Mozilla/5.0',
            'browser'    => 'Chrome',
            'device_os'  => 'Windows 10',
            'ip'         => '10.0.0.1',
            'status'     => 'failed',
            'error_code' => 'incorrect_password',
            'media'      => 'web',
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ], $overrides));
    }

    /**
     * @param array $params
     * @return array
     */
    private function logs($params = [])
    {
        $request = new \WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        return LogsController::getLogs($request)['logs'];
    }

    private function response($params = [])
    {
        $request = new \WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        return LogsController::getLogs($request);
    }

    public function testReturnsLogsNewestFirst()
    {
        $this->log(['username' => 'older', 'created_at' => gmdate('Y-m-d H:i:s', strtotime('-2 days'))]);
        $this->log(['username' => 'newer']);

        $result = $this->logs(['sortBy' => 'created_at', 'sortType' => 'DESC']);

        $this->assertEquals(2, $result['total']);
        $this->assertEquals('newer', $result['data'][0]->username);
    }

    public function testFiltersByStatus()
    {
        $this->log(['status' => 'failed']);
        $this->log(['status' => 'blocked']);
        $this->log(['status' => 'success']);

        $this->assertEquals(1, $this->logs(['statuses' => ['blocked']])['total']);
        $this->assertEquals(2, $this->logs(['statuses' => ['failed', 'blocked']])['total']);
        $this->assertEquals(3, $this->logs(['statuses' => ['all']])['total']);
        $this->assertEquals(3, $this->logs()['total']);
    }

    /**
     * Following one address through the log is the most common reason to search it, and
     * until the logs screen was rebuilt the box did not look at the address column at all.
     */
    public function testSearchesTheAddressAsWellAsTheName()
    {
        $this->log(['username' => 'alice', 'ip' => '10.0.0.1']);
        $this->log(['username' => 'bob', 'ip' => '203.0.113.9']);
        $this->log(['username' => 'carol', 'ip' => '203.0.113.10']);

        $byIp = $this->logs(['search' => '203.0.113.9']);

        $this->assertEquals(1, $byIp['total']);
        $this->assertEquals('bob', $byIp['data'][0]->username);

        // A partial address still matches, so a whole subnet can be pulled up at once.
        $this->assertEquals(2, $this->logs(['search' => '203.0.113.'])['total']);

        $this->assertEquals(1, $this->logs(['search' => 'alice'])['total']);
        $this->assertEquals(0, $this->logs(['search' => 'nobody'])['total']);
    }

    public function testSearchesTheLoginMethod()
    {
        $this->log(['media' => 'web']);
        $this->log(['media' => 'magic_login']);

        $this->assertEquals(1, $this->logs(['search' => 'magic'])['total']);
    }

    /**
     * The table prints these three straight out, so a row without them renders blank cells.
     */
    public function testEveryRowCarriesWhatTheTablePrints()
    {
        $this->log(['media' => 'totp']);

        $log = $this->logs()['data'][0];

        $this->assertNotEmpty($log->human_time_diff);
        $this->assertStringContainsString('ago', $log->human_time_diff);
        $this->assertNotEmpty($log->created_at_human);
        $this->assertEquals('Authenticator app', $log->media_label);
    }

    public function testUnknownLoginMethodsAreNamedRatherThanBlank()
    {
        $this->log(['media' => 'some_provider']);

        $this->assertEquals('Some Provider', $this->logs()['data'][0]->media_label);
    }

    public function testTheEventFilterNarrowsWithinAView()
    {
        $this->log(['status' => 'site_activity', 'media' => 'plugin_activated']);
        $this->log(['status' => 'site_activity', 'media' => 'plugin_updated']);
        $this->log(['status' => 'site_activity', 'media' => 'delete_file']);

        $result = $this->logs(['statuses' => ['site_activity'], 'events' => ['plugin_updated']]);

        $this->assertCount(1, $result['data']);
        $this->assertEquals('plugin_updated', $result['data'][0]->media);
    }

    public function testSeveralEventsCanBeAskedForAtOnce()
    {
        $this->log(['status' => 'site_activity', 'media' => 'plugin_activated']);
        $this->log(['status' => 'site_activity', 'media' => 'plugin_deactivated']);
        $this->log(['status' => 'site_activity', 'media' => 'delete_file']);

        $result = $this->logs([
            'statuses' => ['site_activity'],
            'events'   => ['plugin_activated', 'plugin_deactivated']
        ]);

        $this->assertCount(2, $result['data']);
    }

    /** "all" and an absent filter both mean the same thing: do not narrow. */
    public function testAllEventsMeansEveryEvent()
    {
        $this->log(['status' => 'site_activity', 'media' => 'plugin_activated']);
        $this->log(['status' => 'site_activity', 'media' => 'delete_file']);

        $this->assertCount(2, $this->logs(['events' => ['all']])['data']);
        $this->assertCount(2, $this->logs([])['data']);
    }

    /**
     * The dropdown is built from the rows, so it offers what the view holds and nothing
     * else - a hand-kept list would go stale the first time something new was recorded.
     */
    public function testTheEventListIsBuiltFromTheRowsTheViewCovers()
    {
        $this->log(['status' => 'site_activity', 'media' => 'plugin_activated']);
        $this->log(['status' => 'site_activity', 'media' => 'plugin_activated']);
        $this->log(['status' => 'site_activity', 'media' => 'delete_file']);
        $this->log(['status' => 'failed', 'media' => 'magic_login']);

        $events = $this->response(['view' => 'site_activity', 'statuses' => ['site_activity']])['events'];

        $values = wp_list_pluck($events, 'value');

        $this->assertCount(2, $events, 'Each kind once, however many rows carry it.');
        $this->assertContains('plugin_activated', $values);
        $this->assertContains('delete_file', $values);
        $this->assertNotContains('magic_login', $values, 'Another view\'s events are not this view\'s.');
    }

    public function testTheEventListNamesEachEventRatherThanSlugsIt()
    {
        $this->log(['status' => 'site_activity', 'media' => 'plugin_updated']);

        $events = $this->response(['view' => 'site_activity', 'statuses' => ['site_activity']])['events'];

        $this->assertEquals('Plugin updated', $events[0]['label']);
    }

    /** Otherwise choosing one would collapse the list it was chosen from down to itself. */
    public function testChoosingAnEventDoesNotShortenTheList()
    {
        $this->log(['status' => 'site_activity', 'media' => 'plugin_activated']);
        $this->log(['status' => 'site_activity', 'media' => 'delete_file']);

        $response = $this->response([
            'view'     => 'site_activity',
            'statuses' => ['site_activity'],
            'events'   => ['delete_file']
        ]);

        $this->assertCount(1, $response['logs']['data']);
        $this->assertCount(2, $response['events']);
    }

    /**
     * Only site activity gets the control, so only site activity pays for the query that
     * feeds it. A view that never shows it should not be building its list either.
     */
    public function testNoOtherViewIsOfferedAnEventList()
    {
        $this->log(['status' => 'failed', 'media' => 'web']);
        $this->log(['status' => 'failed', 'media' => 'magic_login']);

        $this->assertEmpty($this->response(['view' => 'failed', 'statuses' => ['failed']])['events']);
        $this->assertEmpty($this->response(['view' => 'all'])['events']);
        $this->assertEmpty($this->response([])['events'], 'No view named means no list.');
    }

    public function testStatusFilterAndSearchApplyTogether()
    {
        $this->log(['status' => 'failed', 'ip' => '203.0.113.9']);
        $this->log(['status' => 'success', 'ip' => '203.0.113.9']);
        $this->log(['status' => 'failed', 'ip' => '10.0.0.1']);

        $result = $this->logs(['statuses' => ['failed'], 'search' => '203.0.113.9']);

        $this->assertEquals(1, $result['total']);
        $this->assertEquals('failed', $result['data'][0]->status);
    }

    /**
     * The log trims itself on a schedule, and the screen says so - so the number it says
     * it with has to come back with the rows rather than from whatever the admin app was
     * booted with.
     */
    public function testItReportsHowLongEntriesAreKept()
    {
        $settings = \FluentAuth\App\Helpers\Helper::getAuthSettings();
        $settings['auto_delete_logs_day'] = 45;
        update_option('__fls_auth_settings', $settings);
        \FluentAuth\App\Helpers\Helper::resetStatics();

        $request = new \WP_REST_Request();

        $this->assertSame(45, LogsController::getLogs($request)['retention']);

        $settings['auto_delete_logs_day'] = 0;
        update_option('__fls_auth_settings', $settings);
        \FluentAuth\App\Helpers\Helper::resetStatics();

        $this->assertSame(
            0,
            LogsController::getLogs($request)['retention'],
            'Nothing is deleted at zero, and the screen says that instead.'
        );
    }

    public function testDeleteLogRemovesJustThatRow()
    {
        $this->log(['username' => 'keep']);
        $this->log(['username' => 'remove']);

        $id = null;

        foreach ($this->logs()['data'] as $log) {
            if ($log->username === 'remove') {
                $id = $log->id;
            }
        }

        $request = new \WP_REST_Request();
        $request->set_param('id', $id);

        LogsController::deleteLog($request);

        $remaining = $this->logs();

        $this->assertEquals(1, $remaining['total']);
        $this->assertEquals('keep', $remaining['data'][0]->username);
    }
}
