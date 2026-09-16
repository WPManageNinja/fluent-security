<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\DashboardController;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

class DashboardControllerTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}fls_auth_logs");

        update_option('__fls_auth_settings', [
            'disable_xmlrpc'          => 'no',
            'disable_users_rest'      => 'no',
            'login_try_limit'         => 5,
            'login_try_timing'        => 30,
            'auto_delete_logs_day'    => 30,
            'notification_user_roles' => [],
            'notification_email'      => '{admin_email}',
            'totp_2fa'                => 'no',
            'email2fa'                => 'no',
            'digest_summary'          => ''
        ]);

        delete_option('__fls_integrity_settings');
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
     * @param string $range
     * @return array
     */
    private function dashboard($range = '-30 days')
    {
        $request = new \WP_REST_Request();
        $request->set_param('day_range', $range);

        return DashboardController::getDashboard($request);
    }

    public function testReturnsEveryPanelThePageDraws()
    {
        $result = $this->dashboard();

        foreach (['range', 'stats', 'chart', 'recent', 'top_ips', 'methods', 'protection'] as $key) {
            $this->assertArrayHasKey($key, $result);
        }

        $this->assertArrayHasKey('threats', $result['recent']);
        $this->assertArrayHasKey('successes', $result['recent']);
    }

    public function testTilesCountEachStatusInTheRange()
    {
        $this->log(['status' => 'success']);
        $this->log(['status' => 'success']);
        $this->log(['status' => 'failed']);
        $this->log(['status' => 'blocked']);

        $stats = [];

        foreach ($this->dashboard()['stats'] as $stat) {
            $stats[$stat['key']] = $stat['value'];
        }

        $this->assertEquals('2', $stats['success']);
        $this->assertEquals('1', $stats['failed']);
        $this->assertEquals('1', $stats['blocked']);
    }

    public function testTilesIgnoreActivityOutsideTheRange()
    {
        $this->log(['status' => 'success', 'created_at' => gmdate('Y-m-d H:i:s', strtotime('-100 days'))]);

        $stats = [];

        foreach ($this->dashboard('-7 days')['stats'] as $stat) {
            $stats[$stat['key']] = $stat['value'];
        }

        $this->assertEquals('0', $stats['success']);
    }

    public function testRecentActivityUsesTheSelectedRange()
    {
        foreach (['failed', 'blocked', 'success'] as $status) {
            $this->log(['status' => $status, 'username' => 'older', 'created_at' => gmdate('Y-m-d H:i:s', strtotime('-100 days'))]);
            $this->log(['status' => $status, 'username' => 'current']);
        }

        $recent = $this->dashboard('-7 days')['recent'];
        $this->assertCount(2, $recent['threats']);
        $this->assertCount(1, $recent['successes']);
        foreach (array_merge($recent['threats'], $recent['successes']) as $row) {
            $this->assertEquals('current', $row['username']);
        }
        $this->assertCount(4, $this->dashboard('all_time')['recent']['threats']);
    }

    public function testAuthenticatorStatusDoesNotInferEnabledFromEnrollment()
    {
        $userId = $this->factory->user->create();
        TotpTwoFaMethod::activate($userId, 'ABCDEFGHIJKLMNOP');
        $protection = $this->dashboard()['protection'];
        $this->assertEquals(1, $protection['two_fa']['enrolled']);
        $this->assertFalse($protection['two_fa_enabled']);

        $settings = get_option('__fls_auth_settings');
        $settings['totp_2fa'] = 'yes';
        update_option('__fls_auth_settings', $settings);
        \FluentAuth\App\Helpers\Helper::resetStatics();
        $this->assertTrue($this->dashboard()['protection']['two_fa_enabled']);
    }

    /**
     * The denominator on the dashboard tile is the people who could enrol, not everybody
     * with an account - and it is the same number the 2FA Enrollment screen shows.
     *
     * The two used to compute it separately and disagreed: a shop with three administrators
     * and thirty-two customers read "0 of 3" on one screen and "0 of 35" on the other. Only
     * the first describes whether the policy has landed; customers are not offered a second
     * factor, so none of them were ever going to appear on the top of the fraction.
     */
    public function testTheTwoFaTileCountsOnlyPeopleWhoCouldEnrol()
    {
        $settings = get_option('__fls_auth_settings');
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        \FluentAuth\App\Helpers\Helper::resetStatics();

        $this->factory->user->create(['role' => 'administrator']);

        foreach (range(1, 6) as $i) {
            $this->factory->user->create(['role' => 'subscriber']);
        }

        $total = $this->dashboard()['protection']['two_fa']['total'];

        $this->assertSame(
            \FluentAuth\App\Http\Controllers\TwoFaController::countEligibleUsers(),
            $total,
            'the dashboard and the enrollment screen read the same number'
        );

        $everyone = (int)(new \WP_User_Query(['number' => 1, 'fields' => 'ID']))->get_total();

        $this->assertLessThan($everyone, $total, 'the six subscribers are not counted');
    }

    /**
     * Nobody is offered a second factor, so there is nobody to count - rather than every
     * account on the site sitting under a zero.
     */
    public function testTheTwoFaTileCountsNobodyWhenNoRoleIsOfferedAFactor()
    {
        $settings = get_option('__fls_auth_settings');
        $settings['totp_2fa'] = 'no';
        $settings['totp_2fa_roles'] = [];
        $settings['passkey_2fa'] = 'no';
        $settings['passkey_2fa_roles'] = [];
        update_option('__fls_auth_settings', $settings);
        \FluentAuth\App\Helpers\Helper::resetStatics();

        $this->factory->user->create(['role' => 'subscriber']);

        $this->assertSame(0, $this->dashboard()['protection']['two_fa']['total']);
    }

    public function testTwoFaTileCountsEnrolledUsers()
    {
        $userId = $this->factory->user->create();
        TotpTwoFaMethod::activate($userId, 'ABCDEFGHIJKLMNOP');

        $tile = null;

        foreach ($this->dashboard()['stats'] as $stat) {
            if ($stat['key'] === 'two_fa') {
                $tile = $stat;
            }
        }

        $this->assertNotNull($tile);
        $this->assertEquals('1', $tile['value']);
        $this->assertStringContainsString('users', $tile['meta']);
    }

    /**
     * The bucket keys are built twice - once by MySQL and once by PHP - and the chart is
     * silently all zeroes if the two disagree. This is the test that catches that.
     */
    public function testChartCountsLandInTheBucketTheyBelongTo()
    {
        $this->log(['status' => 'failed']);
        $this->log(['status' => 'failed']);
        $this->log(['status' => 'success']);

        $chart = $this->dashboard('-7 days')['chart'];

        $this->assertCount(7, $chart['points']);
        $this->assertEquals(3, $chart['max']);

        $today = end($chart['points']);

        $this->assertEquals(2, $today['counts']['failed']);
        $this->assertEquals(1, $today['counts']['success']);
        $this->assertEquals(0, $today['counts']['blocked']);
    }

    public function testChartBucketsMatchTheRangeItCovers()
    {
        $expected = [
            '-0 days'  => 24,  // one bar an hour
            '-7 days'  => 7,
            '-30 days' => 30
        ];

        foreach ($expected as $range => $count) {
            $this->assertCount($count, $this->dashboard($range)['chart']['points'], $range);
        }

        // This month runs from the 1st to today, whenever today is.
        $this->assertCount(
            (int)date('j', current_time('timestamp')),
            $this->dashboard('this_month')['chart']['points']
        );
    }

    public function testChartHasEveryBucketEvenTheEmptyOnes()
    {
        $this->log(['status' => 'failed']);

        $points = $this->dashboard('-7 days')['chart']['points'];

        $this->assertCount(7, $points);

        $empty = array_filter($points, function ($point) {
            return array_sum($point['counts']) === 0;
        });

        $this->assertCount(6, $empty);
    }

    public function testUnknownRangeFallsBackToThirtyDays()
    {
        $result = $this->dashboard('; DROP TABLE wp_users');

        $this->assertEquals('-30 days', $result['range']['key']);
        $this->assertCount(30, $result['chart']['points']);
    }

    public function testTopIpsGroupAttemptsByAddress()
    {
        $this->log(['ip' => '10.0.0.1', 'status' => 'failed']);
        $this->log(['ip' => '10.0.0.1', 'status' => 'blocked', 'username' => 'root']);
        $this->log(['ip' => '10.0.0.1', 'status' => 'failed']);
        $this->log(['ip' => '10.0.0.2', 'status' => 'failed']);
        // Successful logins are not attempts to get in, so they do not belong here.
        $this->log(['ip' => '10.0.0.3', 'status' => 'success']);

        $rows = $this->dashboard()['top_ips'];

        $this->assertCount(2, $rows);
        $this->assertEquals('10.0.0.1', $rows[0]['ip']);
        $this->assertEquals(3, $rows[0]['attempts']);
        $this->assertEquals(2, $rows[0]['usernames']);
        $this->assertEquals('10.0.0.2', $rows[1]['ip']);
    }

    public function testLoginMethodsShareOutSuccessfulLogins()
    {
        $this->log(['status' => 'success', 'media' => 'web']);
        $this->log(['status' => 'success', 'media' => 'web']);
        $this->log(['status' => 'success', 'media' => 'web']);
        $this->log(['status' => 'success', 'media' => 'magic_login']);
        $this->log(['status' => 'failed', 'media' => 'web']);

        $methods = $this->dashboard()['methods'];

        $this->assertCount(2, $methods);
        $this->assertEquals('web', $methods[0]['key']);
        $this->assertEquals(3, $methods[0]['count']);
        $this->assertEquals(75, $methods[0]['percent']);
        $this->assertEquals('magic_login', $methods[1]['key']);
        $this->assertEquals(25, $methods[1]['percent']);
    }

    public function testLoginMethodsNameTheOnesTheyKnow()
    {
        $this->log(['status' => 'success', 'media' => 'totp']);

        $methods = $this->dashboard()['methods'];

        $this->assertEquals('Authenticator app', $methods[0]['label']);
    }

    /**
     * The dashboard used to assemble its own checklist, and the aside used to render it. Both
     * are gone: the aside fetches the security screen's list from the endpoint that screen
     * uses, so there is one answer to "what is wrong with this site" rather than one per
     * screen. Two such lists do not merely duplicate each other - they eventually disagree,
     * and a security tool that contradicts itself has spent the only thing it has.
     *
     * Asserted as an absence because putting it back is the mistake worth catching. What the
     * list contains is covered by SecurityChecksTest and SecurityFindingsTest.
     */
    public function testDoesNotAssembleASecondListOfWhatIsWrongWithTheSite()
    {
        $this->assertArrayNotHasKey('checklist', $this->dashboard());
    }

    public function testApplySecurityCheckEndpointTurnsOnAProtection()
    {
        $request = new \WP_REST_Request();
        $request->set_param('key', 'disable_xmlrpc');

        $result = DashboardController::applySecurityCheck($request);

        $this->assertIsArray($result);
        $this->assertEquals('yes', $result['settings']['disable_xmlrpc']);
        $this->assertArrayHasKey('checklist', $result);
    }

    public function testApplySecurityCheckEndpointRefusesAnythingElse()
    {
        $request = new \WP_REST_Request();
        $request->set_param('key', 'trusted_proxies');

        $this->assertWpErrorWithCode(DashboardController::applySecurityCheck($request), 'unknown_check');
    }

    public function testProtectionReportsTheStandingSetup()
    {
        update_option('__fls_integrity_settings', [
            'status'       => 'self',
            'auto_scan'    => 'yes',
            'is_ok'        => 'no',
            'last_checked' => gmdate('Y-m-d H:i:s', strtotime('-2 hours'))
        ]);

        $protection = $this->dashboard()['protection'];

        $this->assertEquals(30, $protection['retention']);
        $this->assertTrue($protection['scan']['registered']);
        $this->assertFalse($protection['scan']['is_ok']);
        $this->assertNotEmpty($protection['scan']['last_checked']);
        $this->assertArrayHasKey('enrolled', $protection['two_fa']);
    }

    /**
     * The schedule the dashboard reports has to be the one the cron would actually run.
     *
     * `auto_scan` alone is not it: the cron declines unless the site is also connected, so a
     * site left with the flag set after being disconnected would otherwise be shown a daily
     * schedule that never runs.
     *
     * @dataProvider scheduleProvider
     */
    public function testProtectionReportsTheScheduleTheCronWouldRun($settings, $scheduled, $interval)
    {
        update_option('__fls_integrity_settings', $settings);

        $scan = $this->dashboard()['protection']['scan'];

        $this->assertSame($scheduled, $scan['scheduled']);
        $this->assertSame($interval, $scan['interval']);
    }

    public function scheduleProvider()
    {
        return [
            'connected and daily'   => [['status' => 'active', 'auto_scan' => 'yes', 'scan_interval' => 'daily'], true, 'daily'],
            'connected and hourly'  => [['status' => 'active', 'auto_scan' => 'yes', 'scan_interval' => 'hourly'], true, 'hourly'],
            'connected, switched off' => [['status' => 'active', 'auto_scan' => 'no', 'scan_interval' => 'daily'], false, 'daily'],
            'never set up'          => [['status' => 'unregistered', 'auto_scan' => 'no'], false, 'daily'],
            /* The flag survives being disowned; the cron still would not run. */
            'disowned but flagged'  => [['status' => 'disabled', 'auto_scan' => 'yes', 'scan_interval' => 'hourly'], false, 'hourly'],
            'an unknown interval falls back to daily' => [['status' => 'active', 'auto_scan' => 'yes', 'scan_interval' => 'weekly'], true, 'daily'],
        ];
    }

    public function testProtectionSaysWhenTheRelayDisownedTheSite()
    {
        update_option('__fls_integrity_settings', [
            'status'          => 'disabled',
            'auto_scan'       => 'yes',
            'relay_rejection' => 'disabled'
        ]);

        $scan = $this->dashboard()['protection']['scan'];

        $this->assertEquals('disabled', $scan['disconnected']);
        $this->assertFalse($scan['scheduled']);
        $this->assertFalse($scan['registered']);
    }

    public function testProtectionMarksAScanServiceTheSiteRunsItself()
    {
        update_option('__fls_integrity_settings', ['status' => 'self', 'auto_scan' => 'no']);

        $scan = $this->dashboard()['protection']['scan'];

        $this->assertTrue($scan['self_managed']);
        $this->assertFalse($scan['scheduled']);
        $this->assertSame('', $scan['disconnected']);
    }

    public function testRecentListsAreCappedAndNewestFirst()
    {
        for ($i = 0; $i < 10; $i++) {
            $this->log(['status' => 'failed', 'username' => 'user' . $i]);
        }

        $threats = $this->dashboard()['recent']['threats'];

        $this->assertCount(6, $threats);
        $this->assertEquals('user9', $threats[0]['username']);
        $this->assertNotEmpty($threats[0]['time_ago']);
        $this->assertEquals('Windows 10 / Chrome', $threats[0]['browser']);
    }
}
