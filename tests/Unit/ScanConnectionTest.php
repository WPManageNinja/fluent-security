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
