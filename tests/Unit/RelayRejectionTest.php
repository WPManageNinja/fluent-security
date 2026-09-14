<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\IntegrityChecker\IntegrityHelper;

/**
 * What this install does when the alerts relay stops accepting its reports.
 *
 * The site owner can disable or delete a site from the dashboard, and the only way this end
 * ever finds out is by being refused mid-report. The distinction matters: a disabled site is
 * one click from working again, a deleted one has to register from scratch.
 */
class RelayRejectionTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        IntegrityHelper::saveSettings(array_merge(IntegrityHelper::getSettings(), [
            'status'           => 'active',
            'api_id'           => 'api-123',
            'api_key'          => 'key-456',
            'account_email_id' => 'owner@example.com',
            'auto_scan'        => 'yes'
        ]));
    }

    private function response($code, $body)
    {
        return [
            'response' => ['code' => $code, 'message' => ''],
            'body'     => json_encode($body),
            'headers'  => []
        ];
    }

    public function testDisabledSiteStopsReportingButKeepsItsKey()
    {
        $reason = IntegrityHelper::handleReportResponse($this->response(403, [
            'status'     => 'error',
            'error_code' => 'not_connected',
            'message'    => 'This site is not connected.'
        ]));

        $this->assertEquals(IntegrityHelper::RELAY_DISABLED, $reason);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('disabled', $settings['status']);
        $this->assertEquals(IntegrityHelper::RELAY_DISABLED, $settings['relay_rejection']);

        // The key still works on the relay - the owner re-enabling the site is the whole fix.
        $this->assertEquals('api-123', $settings['api_id']);
        $this->assertEquals('key-456', $settings['api_key']);
        $this->assertEquals('yes', $settings['auto_scan']);
    }

    public function testDeletedSiteClearsCredentialsAfterASecondRefusal()
    {
        $unauthorised = $this->response(401, [
            'status'     => 'error',
            'error_code' => 'invalid_key',
            'message'    => 'That key is not valid for this site.'
        ]);

        // A 401 is ambiguous, so the first one only costs a strike.
        $this->assertNull(IntegrityHelper::handleReportResponse($unauthorised));

        $settings = IntegrityHelper::getSettings();
        $this->assertEquals('active', $settings['status']);
        $this->assertEquals(1, $settings['relay_auth_failures']);
        $this->assertEquals('api-123', $settings['api_id']);

        $this->assertEquals(IntegrityHelper::RELAY_REVOKED, IntegrityHelper::handleReportResponse($unauthorised));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('unregistered', $settings['status']);
        $this->assertEquals(IntegrityHelper::RELAY_REVOKED, $settings['relay_rejection']);
        $this->assertSame('', $settings['api_id']);
        $this->assertSame('', $settings['api_key']);
        $this->assertSame('', $settings['account_email_id']);
        $this->assertEquals('no', $settings['auto_scan']);
    }

    public function testASuccessfulReportBetweenRefusalsResetsTheStrike()
    {
        IntegrityHelper::handleReportResponse($this->response(401, ['error_code' => 'invalid_key']));
        $this->assertEquals(1, IntegrityHelper::getSettings()['relay_auth_failures']);

        IntegrityHelper::handleReportResponse($this->response(200, ['status' => 'success']));
        $this->assertEquals(0, IntegrityHelper::getSettings()['relay_auth_failures']);

        // So the next single 401 is a first strike again, not the one that disconnects.
        $this->assertNull(IntegrityHelper::handleReportResponse($this->response(401, ['error_code' => 'invalid_key'])));
        $this->assertEquals('active', IntegrityHelper::getSettings()['status']);
    }

    /**
     * @dataProvider notAVerdictProvider
     */
    public function testTransientFailuresLeaveTheSiteConnected($code, $body)
    {
        $this->assertNull(IntegrityHelper::handleReportResponse($this->response($code, $body)));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertSame('', $settings['relay_rejection']);
        $this->assertEquals(0, $settings['relay_auth_failures']);
    }

    public function notAVerdictProvider()
    {
        return [
            'rate limited'  => [429, ['error_code' => 'rate_limited']],
            'relay is down' => [500, []],
            'bad gateway'   => [502, []],
        ];
    }

    public function testATransportErrorSaysNothingAboutTheSite()
    {
        $this->assertNull(IntegrityHelper::handleReportResponse(new \WP_Error('http_request_failed', 'Connection timed out')));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertSame('', $settings['relay_rejection']);
    }

    /**
     * The relay spells this field `error_code`; read the other spelling too rather than depend
     * on which one a given version sends, since the status code already carries the verdict.
     */
    public function testTheVerdictComesFromTheStatusCodeNotTheBody()
    {
        $reason = IntegrityHelper::handleReportResponse([
            'response' => ['code' => 403, 'message' => ''],
            'body'     => 'not json at all',
            'headers'  => []
        ]);

        $this->assertEquals(IntegrityHelper::RELAY_DISABLED, $reason);
        $this->assertEquals('disabled', IntegrityHelper::getSettings()['status']);
    }

    /**
     * The reconnect button, which only means anything if it actually asks the relay.
     */
    public function testResumingClearsTheRejectionWhenTheRelayAcceptsTheProbe()
    {
        IntegrityHelper::handleReportResponse($this->response(403, ['error_code' => 'not_connected']));
        $this->assertEquals('disabled', IntegrityHelper::getSettings()['status']);

        $captured = null;
        $accept = function ($preempt, $args, $url) use (&$captured) {
            $captured = $url;

            return $this->response(200, ['status' => 'success', 'data' => ['notified' => false]]);
        };

        add_filter('pre_http_request', $accept, 10, 3);
        $result = \FluentAuth\App\Http\Controllers\SecurityScanController::resumeReporting(new \WP_REST_Request());
        remove_filter('pre_http_request', $accept, 10);

        $this->assertStringContainsString('/reports', (string)$captured, 'Resuming must actually probe the relay.');
        $this->assertIsArray($result);

        $settings = IntegrityHelper::getSettings();
        $this->assertEquals('active', $settings['status']);
        $this->assertSame('', $settings['relay_rejection'], 'A relay that accepted the probe leaves nothing to report.');
        $this->assertEquals('yes', $settings['auto_scan']);
    }

    public function testResumingAStillDisabledSiteGoesStraightBackToDisabled()
    {
        IntegrityHelper::handleReportResponse($this->response(403, ['error_code' => 'not_connected']));

        $refuse = function () {
            return $this->response(403, ['error_code' => 'not_connected', 'message' => 'This site is not connected.']);
        };

        add_filter('pre_http_request', $refuse);
        $result = \FluentAuth\App\Http\Controllers\SecurityScanController::resumeReporting(new \WP_REST_Request());
        remove_filter('pre_http_request', $refuse);

        $this->assertWpErrorWithCode($result, 'still_disabled');

        $settings = IntegrityHelper::getSettings();
        $this->assertEquals('disabled', $settings['status']);
        $this->assertEquals(IntegrityHelper::RELAY_DISABLED, $settings['relay_rejection']);
    }

    /**
     * A probe that never reached the relay must not be reported as a reconnection. The site is
     * left reporting again - the schedule will settle it - but the screen is not told that the
     * dashboard confirmed anything, because it did not.
     */
    public function testResumingDoesNotClaimSuccessWhenTheRelayCouldNotBeReached()
    {
        IntegrityHelper::handleReportResponse($this->response(403, ['error_code' => 'not_connected']));

        $down = function () {
            return $this->response(500, []);
        };

        add_filter('pre_http_request', $down);
        $result = \FluentAuth\App\Http\Controllers\SecurityScanController::resumeReporting(new \WP_REST_Request());
        remove_filter('pre_http_request', $down);

        $this->assertWpErrorWithCode($result, 'probe_failed');

        $settings = IntegrityHelper::getSettings();
        $this->assertEquals('active', $settings['status'], 'Reporting is on again; only the confirmation is missing.');
        $this->assertSame('', $settings['relay_rejection']);
    }

    public function testResumingDoesNotClaimSuccessWhenTheRequestFailedOutright()
    {
        IntegrityHelper::handleReportResponse($this->response(403, ['error_code' => 'not_connected']));

        $timeout = function () {
            return new \WP_Error('http_request_failed', 'Connection timed out');
        };

        add_filter('pre_http_request', $timeout);
        $result = \FluentAuth\App\Http\Controllers\SecurityScanController::resumeReporting(new \WP_REST_Request());
        remove_filter('pre_http_request', $timeout);

        $this->assertWpErrorWithCode($result, 'probe_failed');
    }

    public function testResumingIsRefusedWhenNothingIsWaitingToBeReconnected()
    {
        $result = \FluentAuth\App\Http\Controllers\SecurityScanController::resumeReporting(new \WP_REST_Request());

        $this->assertWpErrorWithCode($result, 'invalid_state');
    }

    /**
     * The probe must not re-scan: a button click cannot afford a checksum fetch and a walk of
     * wp-content, and the answer it is waiting for is the relay's, not the scanner's.
     */
    public function testTheProbeAsksTheRelayAndNothingElse()
    {
        IntegrityHelper::handleReportResponse($this->response(403, ['error_code' => 'not_connected']));

        $urls = [];
        $record = function ($preempt, $args, $url) use (&$urls) {
            $urls[] = $url;

            return $this->response(200, ['status' => 'success']);
        };

        add_filter('pre_http_request', $record, 10, 3);
        \FluentAuth\App\Http\Controllers\SecurityScanController::resumeReporting(new \WP_REST_Request());
        remove_filter('pre_http_request', $record, 10);

        $this->assertCount(1, $urls, 'Reconnecting should cost exactly one request: the probe.');
    }

    public function testADisownedSiteDoesNotPostAgain()
    {
        IntegrityHelper::handleReportResponse($this->response(403, ['error_code' => 'not_connected']));

        $posted = false;
        $spy = function () use (&$posted) {
            $posted = true;

            return new \WP_Error('blocked', 'should not be called');
        };

        add_filter('pre_http_request', $spy);
        IntegrityHelper::maybeSendScanReport();
        remove_filter('pre_http_request', $spy);

        $this->assertFalse($posted, 'A site the relay disowned must not keep posting reports.');
    }
}
