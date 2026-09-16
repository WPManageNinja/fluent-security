<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SecurityScanController;
use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * Connecting a site to the alerts relay, both ways in.
 *
 * Scheduling has to come on with the connection. A connected site with the schedule off sends
 * nothing at all, and does it invisibly - the screen says connected, the dashboard lists the
 * site, and no report ever arrives.
 */
class ScanConnectionTest extends BaseTestCase
{
    private function relayReturns($status, $body)
    {
        $handler = function () use ($status, $body) {
            return [
                'response' => ['code' => $status, 'message' => ''],
                'body'     => json_encode($body),
                'headers'  => []
            ];
        };

        add_filter('pre_http_request', $handler);

        return $handler;
    }

    private function request($params)
    {
        $request = new \WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        return $request;
    }

    /**
     * The site key never leaves the server.
     *
     * Not an exfiltration worry - the reader is an administrator who could read the option
     * row anyway - but a database row and a JSON response are different exposures. wp-admin
     * runs a crowd of third-party scripts nobody audited for this, and the key can post
     * forged reports and call `disable`. That second one is why it is worth the care: it
     * switches a site's monitoring off, and the only evidence is scans that stop arriving,
     * which is the signal nobody notices.
     *
     * Every route is covered rather than the obvious one, because the failure mode is a
     * ninth return statement added later by somebody who never read this.
     *
     * @dataProvider settingsCarryingRoutes
     */
    public function testTheSiteKeyIsNeverSentToTheBrowser($call)
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status'           => 'active',
            'api_id'           => 'site_probe',
            'api_key'          => 'fask_the_actual_secret',
            'account_email_id' => 'owner@example.com',
            'auto_scan'        => 'yes'
        ]));

        $handler = function () {
            return [
                'response' => ['code' => 200, 'message' => ''],
                'body'     => json_encode(['status' => 'success', 'data' => ['api_id' => 'site_probe']]),
                'headers'  => []
            ];
        };

        /*
         * The settings route builds an extension inventory, which asks WordPress for the
         * update transients - a network call in the middle of a unit test if it is not
         * answered here, and a fatal on a machine with no internet.
         */
        $transient = function () {
            /*
             * `no_update` has to hold something. The inventory treats a transient with no
             * entries at all as never having been fetched and forces a real update check,
             * which is the network call this stub exists to avoid.
             */
            return (object)[
                'last_checked' => time(),
                'response'     => [],
                'no_update'    => ['a-plugin/a-plugin.php' => (object)['slug' => 'a-plugin']]
            ];
        };

        add_filter('pre_site_transient_update_plugins', $transient);
        add_filter('pre_site_transient_update_themes', $transient);
        add_filter('pre_http_request', $handler);

        $result = call_user_func($call);

        remove_filter('pre_http_request', $handler);
        remove_filter('pre_site_transient_update_themes', $transient);
        remove_filter('pre_site_transient_update_plugins', $transient);

        $wire = json_encode(is_wp_error($result) ? $result->get_error_data() : $result);

        $this->assertStringNotContainsString('fask_the_actual_secret', (string)$wire);
    }

    public function settingsCarryingRoutes()
    {
        $req = function ($params = []) {
            $request = new \WP_REST_Request();

            foreach ($params as $key => $value) {
                $request->set_param($key, $value);
            }

            return $request;
        };

        return [
            'get settings'    => [function () use ($req) {
                return SecurityScanController::getSettings($req());
            }],
            'update schedule' => [function () use ($req) {
                return SecurityScanController::updateScheduleScan($req(['auto_scan' => 'yes', 'scan_interval' => 'daily']));
            }],
            'reset api'       => [function () use ($req) {
                return SecurityScanController::resetApi($req());
            }],
        ];
    }

    /**
     * And the replacement says only what is safe to say: that one exists.
     */
    public function testTheResponseSaysOnlyThatAKeyExists()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'active', 'api_key' => 'fask_the_actual_secret'
        ]));

        $settings = SecurityScanController::getSettings(new \WP_REST_Request())['settings'];

        $this->assertArrayNotHasKey('api_key', $settings);
        $this->assertTrue($settings['has_api_key']);

        /* Withheld from the response, not thrown away - the site still reports with it. */
        $this->assertEquals('fask_the_actual_secret', IntegrityHelper::getSettings()['api_key']);

        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), ['api_key' => '']));

        $this->assertFalse(SecurityScanController::getSettings(new \WP_REST_Request())['settings']['has_api_key']);
    }

    /**
     * No credential ever appears in a URL.
     *
     * A key in a query string is written to the web server's access log, to every proxy in
     * front of it, and to the Referer of anything the page goes on to load - several copies of
     * a live credential in places nobody is guarding, and none of them rotate when the key
     * does. Pinned across every route because this is the kind of thing that comes back: one
     * add_query_arg written for convenience and the whole estate is logging keys again.
     *
     * @dataProvider credentialCarryingCalls
     */
    public function testNoCredentialTravelsInAUrl($call)
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status'  => 'active',
            'api_id'  => 'api-secret-id',
            'api_key' => 'key-secret-value'
        ]));

        $urls = [];
        $handler = function ($preempt, $args, $url) use (&$urls) {
            $urls[] = $url;

            return [
                'response' => ['code' => 200, 'message' => ''],
                'body'     => json_encode(['status' => 'success', 'data' => ['api_id' => 'api-secret-id']]),
                'headers'  => []
            ];
        };

        add_filter('pre_http_request', $handler, 10, 3);
        call_user_func($call);
        remove_filter('pre_http_request', $handler, 10);

        $this->assertNotEmpty($urls, 'The call under test has to actually make a request.');

        foreach ($urls as $url) {
            $this->assertStringNotContainsString('key-secret-value', $url, 'A key must never be in a URL.');
            $this->assertStringNotContainsString('api_key=', $url);
        }
    }

    public function credentialCarryingCalls()
    {
        return [
            'confirm' => [function () {
                \FluentAuth\App\Services\IntegrityChecker\Api::confirmSite([
                    'api_id' => 'api-secret-id', 'api_key' => 'key-secret-value'
                ]);
            }],
            'disable' => [function () {
                \FluentAuth\App\Services\IntegrityChecker\Api::disableApi();
            }],
        ];
    }

    public function testConfirmingTheEmailedKeyTurnsOnDailyScanning()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status'           => 'pending',
            'api_id'           => 'api-123',
            'account_email_id' => 'owner@example.com'
        ]));

        $handler = $this->relayReturns(200, ['status' => 'success', 'data' => ['api_id' => 'api-123']]);

        $result = SecurityScanController::registerSite($this->request([
            'status' => 'pending',
            'info'   => ['email' => 'owner@example.com', 'full_name' => 'Site Owner', 'api_key' => 'key-456']
        ]));

        remove_filter('pre_http_request', $handler);

        $this->assertIsArray($result);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertEquals('yes', $settings['auto_scan'], 'Connecting must switch scheduled scanning on.');
        $this->assertEquals('daily', $settings['scan_interval']);
        $this->assertEquals('key-456', $settings['api_key']);
    }

    public function testConfirmingStopsAskingForTheTokenItJustAccepted()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'pending',
            'api_id' => 'api-123'
        ]));

        $handler = $this->relayReturns(200, ['status' => 'success', 'data' => ['api_id' => 'api-123']]);

        $result = SecurityScanController::registerSite($this->request([
            'status' => 'pending',
            'info'   => ['email' => 'owner@example.com', 'full_name' => 'Site Owner', 'api_key' => 'key-456']
        ]));

        remove_filter('pre_http_request', $handler);

        $this->assertStringNotContainsString('provide the API token', $result['message']);
    }

    public function testPastingAnAccountKeyTurnsOnDailyScanning()
    {
        $handler = $this->relayReturns(200, [
            'status' => 'success',
            'data'   => ['api_id' => 'api-789', 'api_key' => 'site-key-789']
        ]);

        $result = SecurityScanController::registerSite($this->request([
            'status'  => 'connect',
            'api_key' => 'fa_live_accountkey'
        ]));

        remove_filter('pre_http_request', $handler);

        $this->assertIsArray($result);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertEquals('yes', $settings['auto_scan']);
        $this->assertEquals('daily', $settings['scan_interval']);
        $this->assertEquals('site-key-789', $settings['api_key']);
    }

    /**
     * Reconnecting has to clear the standing refusal, or the cron reads a site that is active
     * and disowned at the same time and the screen offers a reconnect for a live connection.
     */
    public function testReconnectingClearsAnEarlierRejection()
    {
        IntegrityHelper::markRelayRejected(IntegrityHelper::RELAY_DISABLED);
        $this->assertEquals('disabled', IntegrityHelper::getSettings()['status']);

        $handler = $this->relayReturns(200, [
            'status' => 'success',
            'data'   => ['api_id' => 'api-789', 'api_key' => 'site-key-789']
        ]);

        SecurityScanController::registerSite($this->request([
            'status'  => 'connect',
            'api_key' => 'fa_live_accountkey'
        ]));

        remove_filter('pre_http_request', $handler);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertSame('', $settings['relay_rejection']);
        $this->assertEquals(0, $settings['relay_auth_failures']);
    }

    /**
     * @dataProvider intervalProvider
     */
    public function testEachScheduleWaitsLessThanItsOwnPeriod($interval, $period)
    {
        $seconds = IntegrityHelper::getScanIntervalSeconds($interval);

        $this->assertLessThan($period, $seconds, 'An interval equal to its own period is a coin toss against an hourly cron.');
        $this->assertGreaterThan($period - 3600, $seconds, 'And it must not be short enough to fire a whole tick early.');
    }

    public function intervalProvider()
    {
        return [
            'hourly'        => ['hourly', 3600],
            'every 6 hours' => ['six_hourly', 21600],
            'every 12 hours' => ['twelve_hourly', 43200],
            'daily'         => ['daily', 86400],
        ];
    }

    public function testAnUnknownIntervalFallsBackToDaily()
    {
        $this->assertEquals('daily', IntegrityHelper::normaliseScanInterval('fortnightly'));
        $this->assertEquals('daily', IntegrityHelper::normaliseScanInterval(''));
        $this->assertEquals(IntegrityHelper::getScanIntervalSeconds('daily'), IntegrityHelper::getScanIntervalSeconds('fortnightly'));
    }

    public function testTheScheduleFormRefusesAnIntervalItDoesNotKnow()
    {
        $result = SecurityScanController::updateScheduleScan($this->request([
            'auto_scan'     => 'yes',
            'scan_interval' => 'every_other_tuesday'
        ]));

        $this->assertWpErrorWithCode($result, 'invalid_data');
    }

    public function testTheScheduleFormAcceptsEveryKnownInterval()
    {
        foreach (array_keys(IntegrityHelper::getScanIntervals()) as $interval) {
            $result = SecurityScanController::updateScheduleScan($this->request([
                'auto_scan'     => 'yes',
                'scan_interval' => $interval
            ]));

            $this->assertIsArray($result, $interval . ' should be accepted');
            $this->assertEquals($interval, IntegrityHelper::getSettings()['scan_interval']);
        }
    }

    /**
     * Reconnecting mints a new row on the relay, with nothing reported to it. The previous
     * connection's timestamp must not gate the first report of the new one, or a freshly
     * connected site stays silent for most of a day while the dashboard says it is still
     * awaiting a first scan.
     */
    public function testConnectingClearsTheIntervalGateFromAnEarlierConnection()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status'           => 'pending',
            'api_id'           => 'api-123',
            'last_report_sent' => gmdate('Y-m-d H:i:s', strtotime('-20 minutes'))
        ]));

        $handler = $this->relayReturns(200, ['status' => 'success', 'data' => ['api_id' => 'api-123']]);

        SecurityScanController::registerSite($this->request([
            'status' => 'pending',
            'info'   => ['email' => 'owner@example.com', 'full_name' => 'Site Owner', 'api_key' => 'key-456']
        ]));

        remove_filter('pre_http_request', $handler);

        $this->assertSame('', IntegrityHelper::getSettings()['last_report_sent']);
    }

    public function testPastingAnAccountKeyAlsoClearsTheIntervalGate()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'last_report_sent' => gmdate('Y-m-d H:i:s', strtotime('-20 minutes'))
        ]));

        $handler = $this->relayReturns(200, [
            'status' => 'success',
            'data'   => ['api_id' => 'api-789', 'api_key' => 'site-key-789']
        ]);

        SecurityScanController::registerSite($this->request([
            'status'  => 'connect',
            'api_key' => 'fa_live_accountkey'
        ]));

        remove_filter('pre_http_request', $handler);

        $this->assertSame('', IntegrityHelper::getSettings()['last_report_sent']);
    }

    /**
     * A scan somebody ran themselves has to reach the relay too, or "I scanned and the
     * dashboard still says it is waiting" is the accurate description of a working system.
     */
    public function testAScanRunByHandIsReported()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status'    => 'active',
            'api_id'    => 'api-123',
            'api_key'   => 'key-456',
            'auto_scan' => 'yes'
        ]));

        $urls = [];
        $record = function ($preempt, $args, $url) use (&$urls) {
            $urls[] = $url;

            return ['response' => ['code' => 200, 'message' => ''], 'body' => json_encode(['status' => 'success']), 'headers' => []];
        };

        add_filter('pre_http_request', $record, 10, 3);
        IntegrityHelper::reportScanIfConnected();
        remove_filter('pre_http_request', $record, 10);

        $this->assertCount(1, $urls);
        $this->assertStringContainsString('/reports', $urls[0]);

        /* And it counts against the interval, so the cron does not repeat it minutes later. */
        $this->assertNotEmpty(IntegrityHelper::getSettings()['last_report_sent']);
    }

    /**
     * @dataProvider unreportedProvider
     */
    public function testAScanIsNotReportedWhenTheSiteDoesNotReport($settings)
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), $settings));

        $posted = false;
        $spy = function () use (&$posted) {
            $posted = true;

            return new \WP_Error('blocked', 'should not be called');
        };

        add_filter('pre_http_request', $spy);
        $this->assertNull(IntegrityHelper::reportScanIfConnected());
        remove_filter('pre_http_request', $spy);

        $this->assertFalse($posted);
    }

    public function unreportedProvider()
    {
        return [
            'never connected'      => [['status' => 'unregistered', 'auto_scan' => 'no']],
            'schedule switched off' => [['status' => 'active', 'auto_scan' => 'no']],
            'scanning without the service' => [['status' => 'self', 'auto_scan' => 'yes']],
            'disowned by the relay' => [['status' => 'disabled', 'auto_scan' => 'yes']],
        ];
    }

    /**
     * The first step only registers - the key arrives by email and nothing is connected yet,
     * so there is nothing to schedule.
     */
    public function testRegisteringDoesNotScheduleAnythingBeforeTheKeyIsConfirmed()
    {
        $handler = $this->relayReturns(200, ['status' => 'success', 'data' => ['api_id' => 'api-123']]);

        SecurityScanController::registerSite($this->request([
            'status' => 'unregistered',
            'info'   => ['email' => 'owner@example.com', 'full_name' => 'Site Owner']
        ]));

        remove_filter('pre_http_request', $handler);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('pending', $settings['status']);
        $this->assertEquals('no', $settings['auto_scan']);
    }

    public function testAFailedConfirmationConnectsNothing()
    {
        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status' => 'pending',
            'api_id' => 'api-123'
        ]));

        $handler = $this->relayReturns(401, ['status' => 'error', 'message' => 'That key is not valid for this site.']);

        $result = SecurityScanController::registerSite($this->request([
            'status' => 'pending',
            'info'   => ['email' => 'owner@example.com', 'full_name' => 'Site Owner', 'api_key' => 'wrong-key']
        ]));

        remove_filter('pre_http_request', $handler);

        $this->assertWPError($result);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('pending', $settings['status']);
        $this->assertEquals('no', $settings['auto_scan'], 'A rejected key must not switch scanning on.');
    }
}
