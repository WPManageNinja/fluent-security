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

    /**
     * A refusal in the shape the relay actually sends one.
     *
     * Built here rather than inline so no test can pass on an envelope the relay would never
     * produce - which is what the old fixtures did, omitting `status` entirely and still
     * being read as a verdict.
     */
    private function refusal($code, $errorCode, $message = 'Refused.')
    {
        return $this->response($code, [
            'status'     => 'error',
            'error_code' => $errorCode,
            'message'    => $message
        ]);
    }

    /**
     * Push the first refusal back beyond the grace window.
     *
     * Two refusals only destroy a credential when they are an hour apart as well as
     * consecutive - see IntegrityHelper::RELAY_REVOKE_GRACE - and a test that ran in
     * milliseconds would otherwise never reach the second one.
     */
    private function ageTheFirstRefusal()
    {
        $settings = IntegrityHelper::getSettings();
        $settings['relay_auth_failed_at'] = time() - IntegrityHelper::RELAY_REVOKE_GRACE - 60;
        IntegrityHelper::saveSettings($settings);
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
        $unauthorised = $this->refusal(401, 'invalid_key', 'That key is not valid for this site.');

        // A refusal is ambiguous, so the first one only costs a strike.
        $this->assertNull(IntegrityHelper::handleReportResponse($unauthorised));

        $settings = IntegrityHelper::getSettings();
        $this->assertEquals('active', $settings['status']);
        $this->assertEquals(1, $settings['relay_auth_failures']);
        $this->assertEquals('api-123', $settings['api_id']);

        $this->ageTheFirstRefusal();

        $this->assertEquals(IntegrityHelper::RELAY_REVOKED, IntegrityHelper::handleReportResponse($unauthorised));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('unregistered', $settings['status']);
        $this->assertEquals(IntegrityHelper::RELAY_REVOKED, $settings['relay_rejection']);
        $this->assertSame('', $settings['api_id']);
        $this->assertSame('', $settings['api_key']);
        $this->assertSame('', $settings['account_email_id']);
        $this->assertEquals('no', $settings['auto_scan']);
    }

    /**
     * The id survives the credential it belonged to.
     *
     * It is the only thing that finds this site at the other end once the row is gone: the
     * relay files a tombstone under the api_id, and its console can look one up by id but not
     * by site address - which is exactly the search somebody with a superseded connection
     * tries first, and the one that returns nothing. Clearing it destroyed the reference that
     * makes the support ticket tractable, at the moment the ticket gets raised.
     */
    public function testTheConnectionIdSurvivesARevocationButTheKeyDoesNot()
    {
        $unauthorised = $this->refusal(401, 'invalid_key');

        IntegrityHelper::handleReportResponse($unauthorised);
        $this->ageTheFirstRefusal();
        IntegrityHelper::handleReportResponse($unauthorised);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('api-123', $settings['relay_retired_api_id'], 'The reference has to outlive the row.');
        $this->assertSame('', $settings['api_key'], 'The key is a secret and must not.');
        $this->assertSame('', $settings['api_id'], 'Kept apart from the live field, so nothing reads it as one.');
    }

    /**
     * Being switched off is not losing the row, so there is nothing retired to quote.
     */
    public function testADisabledSiteRetiresNothing()
    {
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));

        $settings = IntegrityHelper::getSettings();

        $this->assertSame('', $settings['relay_retired_api_id']);
        $this->assertEquals('api-123', $settings['api_id'], 'A disabled site keeps its working credential.');
    }

    public function testReconnectingForgetsTheRetiredId()
    {
        $unauthorised = $this->refusal(401, 'invalid_key');

        IntegrityHelper::handleReportResponse($unauthorised);
        $this->ageTheFirstRefusal();
        IntegrityHelper::handleReportResponse($unauthorised);

        $this->assertNotSame('', IntegrityHelper::getSettings()['relay_retired_api_id']);

        IntegrityHelper::clearRelayRejection();

        $this->assertSame('', IntegrityHelper::getSettings()['relay_retired_api_id']);
    }

    public function testASuccessfulReportBetweenRefusalsResetsTheStrike()
    {
        IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_key'));
        $this->assertEquals(1, IntegrityHelper::getSettings()['relay_auth_failures']);

        IntegrityHelper::handleReportResponse($this->response(200, ['status' => 'success']));
        $this->assertEquals(0, IntegrityHelper::getSettings()['relay_auth_failures']);

        // So the next single refusal is a first strike again, not the one that disconnects.
        $this->assertNull(IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_key')));
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
     * The relay's explanation is kept, because the generic sentence cannot be right for
     * every cause. "This usually means the site was deleted" is actively wrong for the
     * commonest cause that is not a deletion: a staging clone copied from the database,
     * which keeps `siteurl` and so looks to the relay like the same site connecting again.
     */
    public function testTheRelaysExplanationIsKeptForTheScreen()
    {
        $this->assertNull(IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_key')));
        $this->ageTheFirstRefusal();

        IntegrityHelper::handleReportResponse($this->response(401, [
            'status'     => 'error',
            'error_code' => 'invalid_key',
            'reason'     => 'superseded',
            'message'    => 'This connection was replaced when the same site address was connected again.'
        ]));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals(IntegrityHelper::RELAY_REVOKED, $settings['relay_rejection']);
        $this->assertEquals('superseded', $settings['relay_rejection_reason']);
        $this->assertStringContainsString('same site address', $settings['relay_rejection_note']);
    }

    /**
     * `reason` is a hint for choosing a sentence, never a thing decisions are made on. A
     * cause this build has never heard of has to behave exactly like one it knows, or the
     * relay could not add one without stranding every install that predates it.
     */
    public function testAnUnknownReasonChangesNothingAboutWhatHappens()
    {
        $this->assertNull(IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_key')));
        $this->ageTheFirstRefusal();

        $reason = IntegrityHelper::handleReportResponse($this->response(401, [
            'status'     => 'error',
            'error_code' => 'invalid_key',
            'reason'     => 'some_cause_invented_next_year',
            'message'    => 'Something new.'
        ]));

        $this->assertEquals(IntegrityHelper::RELAY_REVOKED, $reason);
        $this->assertEquals('unregistered', IntegrityHelper::getSettings()['status']);
    }

    /**
     * The note is drawn on a screen and arrives over the network, so it is sanitised and
     * bounded here rather than trusted to be either.
     */
    public function testTheExplanationIsSanitisedAndBounded()
    {
        IntegrityHelper::handleReportResponse($this->response(403, [
            'status'     => 'error',
            'error_code' => 'not_connected',
            'reason'     => 'removed<script>',
            'message'    => '<script>alert(1)</script>' . str_repeat('x', 900)
        ]));

        $settings = IntegrityHelper::getSettings();

        $this->assertStringNotContainsString('<script>', $settings['relay_rejection_note']);
        $this->assertLessThanOrEqual(400, strlen($settings['relay_rejection_note']));
        $this->assertStringNotContainsString('<', $settings['relay_rejection_reason']);
    }

    public function testReconnectingForgetsTheOldExplanation()
    {
        IntegrityHelper::handleReportResponse($this->response(403, [
            'status' => 'error', 'error_code' => 'not_connected', 'reason' => 'removed', 'message' => 'Gone.'
        ]));

        $this->assertNotSame('', IntegrityHelper::getSettings()['relay_rejection_note']);

        IntegrityHelper::handleReportResponse($this->response(200, ['status' => 'success']));

        $settings = IntegrityHelper::getSettings();

        $this->assertSame('', $settings['relay_rejection_note']);
        $this->assertSame('', $settings['relay_rejection_reason']);
    }

    /**
     * The verdict is the JSON, not the status code - and this is the case that forced it.
     *
     * dash.fluentauth.com sits behind Cloudflare, so a WAF rule or a zone-level block answers
     * 403 with an HTML body from the edge, before the relay runs. Read as a verdict, that is
     * every install on the internet disconnecting itself the day somebody tightens a firewall
     * rule - and each one then needs its owner to register again by email.
     *
     * @dataProvider notFromTheRelayProvider
     */
    public function testARefusalThatDidNotComeFromTheRelayIsNotAVerdict($code, $body)
    {
        $reason = IntegrityHelper::handleReportResponse([
            'response' => ['code' => $code, 'message' => ''],
            'body'     => $body,
            'headers'  => []
        ]);

        $this->assertNull($reason);

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertSame('', $settings['relay_rejection']);
        $this->assertEquals(0, $settings['relay_auth_failures']);
        $this->assertEquals('api-123', $settings['api_id'], 'The credential must survive an edge refusal.');
    }

    public function notFromTheRelayProvider()
    {
        return [
            'Cloudflare 1020 block page' => [403, '<!DOCTYPE html><html><head><title>Access denied</title></head></html>'],
            'edge 401 challenge'         => [401, '<html>Attention Required!</html>'],
            'empty body'                 => [403, ''],
            'json but not an error'      => [403, '{"status":"success"}'],
            'error with no code'         => [403, '{"status":"error","message":"nope"}'],
            'the wrong field name'       => [403, '{"status":"error","code":"not_connected"}'],
        ];
    }

    /**
     * The relay answers 401 for two different things, and only one of them is a revocation.
     * `invalid_request` means this plugin sent an empty pair - our own bug, which must not
     * spend the site's revocation budget.
     */
    public function testAMalformedRequestOfOurOwnIsNotARevocation()
    {
        $this->assertNull(IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_request')));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertEquals(0, $settings['relay_auth_failures'], 'A client-side bug costs no strike.');
        $this->assertEquals('api-123', $settings['api_id']);
    }

    /**
     * Consecutive is not enough on its own. Two refusals inside a minute are far more likely
     * to be one bad deploy at the relay than a site that was really deleted, and the two
     * outcomes are not equally cheap to get wrong: a slow revocation wastes a few reports, a
     * fast one destroys a working credential.
     */
    public function testTwoRefusalsInQuickSuccessionDoNotDestroyTheCredential()
    {
        $unauthorised = $this->refusal(401, 'invalid_key');

        $this->assertNull(IntegrityHelper::handleReportResponse($unauthorised));
        $this->assertNull(IntegrityHelper::handleReportResponse($unauthorised));
        $this->assertNull(IntegrityHelper::handleReportResponse($unauthorised));

        $settings = IntegrityHelper::getSettings();

        $this->assertEquals('active', $settings['status']);
        $this->assertEquals('api-123', $settings['api_id']);
        $this->assertEquals('key-456', $settings['api_key']);
    }

    /**
     * A site that reported cleanly for months and is refused once must not then be one
     * refusal away from disconnection for ever.
     */
    public function testASuccessfulReportClearsTheGraceWindowAsWellAsTheStrike()
    {
        IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_key'));
        $this->ageTheFirstRefusal();

        IntegrityHelper::handleReportResponse($this->response(200, ['status' => 'success']));

        $this->assertEquals(0, IntegrityHelper::getSettings()['relay_auth_failed_at']);

        // A fresh first strike, not the one that disconnects.
        $this->assertNull(IntegrityHelper::handleReportResponse($this->refusal(401, 'invalid_key')));
        $this->assertEquals('active', IntegrityHelper::getSettings()['status']);
    }

    /**
     * The reconnect button, which only means anything if it actually asks the relay.
     */
    public function testResumingClearsTheRejectionWhenTheRelayAcceptsTheProbe()
    {
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));
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
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));

        $refuse = function () {
            return $this->refusal(403, 'not_connected', 'This site is not connected.');
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
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));

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
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));

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
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));

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
        IntegrityHelper::handleReportResponse($this->refusal(403, 'not_connected'));

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
