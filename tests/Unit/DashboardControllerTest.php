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
        update_user_meta($userId, TotpTwoFaMethod::META_SECRET, 'ABCDEFGHIJKLMNOP');
        $protection = $this->dashboard()['protection'];
        $this->assertEquals(1, $protection['two_fa']['enrolled']);
        $this->assertFalse($protection['two_fa_enabled']);

        $settings = get_option('__fls_auth_settings');
        $settings['totp_2fa'] = 'yes';
        update_option('__fls_auth_settings', $settings);
        \FluentAuth\App\Helpers\Helper::resetStatics();
        $this->assertTrue($this->dashboard()['protection']['two_fa_enabled']);
    }

    public function testTwoFaTileCountsEnrolledUsers()
    {
        $userId = $this->factory->user->create();
        update_user_meta($userId, TotpTwoFaMethod::META_SECRET, 'ABCDEFGHIJKLMNOP');

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
