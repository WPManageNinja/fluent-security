<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\LoginSecurityHandler;

/**
 * Application Password auth (REST / XML-RPC over Basic auth) bypasses the
 * `authenticate` filter chain entirely, so it needs its own wiring into the
 * login attempt limit. These tests pin that wiring down.
 */
class LoginSecurityHandlerTest extends BaseTestCase
{
    private $handler;

    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_auth_logs");

        $this->handler = new LoginSecurityHandler();

        unset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
    }

    public function tearDown(): void
    {
        unset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
        parent::tearDown();
    }

    private function seedFailedAttempts($count)
    {
        global $wpdb;

        for ($i = 0; $i < $count; $i++) {
            $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
                'username'   => 'admin',
                'ip'         => Helper::getIp(),
                'status'     => 'failed',
                'media'      => 'app_password',
                'count'      => 1,
                'created_at' => current_time('mysql'),
                'updated_at' => current_time('mysql'),
            ]);
        }
    }

    private function countRows($status)
    {
        global $wpdb;

        return (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = %s",
            $status
        ));
    }

    public function testAppPasswordAuthIsAllowedWhenUnderTheLimit()
    {
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->seedFailedAttempts(2);

        $this->assertTrue($this->handler->maybeBlockAppPasswordAuth(true));
    }

    public function testAppPasswordAuthIsBlockedOnceTheLimitIsExceeded()
    {
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        // Default limit is 5 within 30 minutes.
        $this->seedFailedAttempts(6);

        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));
        $this->assertSame(1, $this->countRows('blocked'));
    }

    /**
     * Core calls wp_is_application_passwords_available() more than once per request.
     * The block must be resolved once so a single attempt is not counted twice.
     */
    public function testRepeatedChecksInOneRequestOnlyRecordTheBlockOnce()
    {
        global $wpdb;

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->seedFailedAttempts(6);

        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));
        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));
        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));

        $this->assertSame(1, $this->countRows('blocked'));

        $blockedCount = (int)$wpdb->get_var(
            "SELECT `count` FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = 'blocked' LIMIT 1"
        );

        $this->assertSame(1, $blockedCount);
    }

    /**
     * The same filter gates the Application Passwords UI on the profile screen.
     * Requests without Basic auth credentials must be left completely alone,
     * otherwise a blocked IP would also hide the UI from a legitimate admin.
     */
    public function testRequestsWithoutBasicAuthCredentialsAreUntouched()
    {
        $this->seedFailedAttempts(20);

        $this->assertTrue($this->handler->maybeBlockAppPasswordAuth(true));
        $this->assertSame(0, $this->countRows('blocked'));
    }

    public function testItNeverReEnablesAppPasswordsThatAreAlreadyDisabled()
    {
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(false));
    }

    public function testFailedAppPasswordAttemptIsLoggedAndCountsTowardsTheLimit()
    {
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $error = new \WP_Error('incorrect_password', 'The provided password is an invalid application password.');

        $this->handler->logFailedAppPasswordAuth($error);

        global $wpdb;
        $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = 'failed' LIMIT 1");

        $this->assertNotNull($row);
        $this->assertSame('admin', $row->username);
        $this->assertSame('app_password', $row->media);
        $this->assertSame('incorrect_password', $row->error_code);
        $this->assertSame(Helper::getIp(), $row->ip);
    }

    /**
     * XML-RPC carries credentials in the request body, not Basic auth headers, and
     * that path already fires `wp_login_failed`. Logging here too would double count.
     */
    public function testFailedAttemptWithoutBasicAuthCredentialsIsNotLogged()
    {
        $error = new \WP_Error('incorrect_password', 'The provided password is an invalid application password.');

        $this->handler->logFailedAppPasswordAuth($error);

        $this->assertSame(0, $this->countRows('failed'));
    }

    public function testMissingUserAgentDoesNotBreakLogging()
    {
        $originalAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : null;
        unset($_SERVER['HTTP_USER_AGENT']);

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        try {
            $this->handler->logFailedAppPasswordAuth(new \WP_Error('incorrect_password', 'nope'));
            $this->assertSame(1, $this->countRows('failed'));
        } finally {
            if ($originalAgent !== null) {
                $_SERVER['HTTP_USER_AGENT'] = $originalAgent;
            }
        }
    }

    private function blockedRow()
    {
        global $wpdb;

        return $wpdb->get_row("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = 'blocked' LIMIT 1");
    }

    /**
     * checkLoginAttempt() used to bump the blocked row's count and then logBlockedAuth()
     * bumped it again, so `count` grew by 2 per blocked attempt.
     */
    public function testEachBlockedAttemptIsCountedExactlyOnce()
    {
        $this->seedFailedAttempts(6);

        // 4 separate requests, each hitting the limit. First creates the row, rest bump it.
        for ($i = 0; $i < 4; $i++) {
            $handler = new LoginSecurityHandler();
            $_SERVER['PHP_AUTH_USER'] = 'admin';
            $_SERVER['PHP_AUTH_PW'] = 'wrong password';
            $this->assertFalse($handler->maybeBlockAppPasswordAuth(true));
        }

        $this->assertSame(1, $this->countRows('blocked'), 'Only one blocked row should exist');
        $this->assertSame(4, (int)$this->blockedRow()->count);
    }

    public function testBlockedAttemptsOnTheWebLoginPathAreCountedOnceToo()
    {
        $this->seedFailedAttempts(6);

        for ($i = 0; $i < 3; $i++) {
            $handler = new LoginSecurityHandler();
            $error = $handler->maybeCheckLoginAttempts(
                new \WP_Error('incorrect_password', 'nope'),
                'admin',
                'wrong password'
            );
            $this->assertWpErrorWithCode($error, 'login_error');
        }

        $this->assertSame(1, $this->countRows('blocked'));
        $this->assertSame(3, (int)$this->blockedRow()->count);
    }

    /**
     * The lockout must keep sliding while attempts continue, so `created_at` is still
     * refreshed on every blocked attempt even though the count is no longer bumped here.
     */
    public function testBlockedAttemptRefreshesTheLockoutWindow()
    {
        global $wpdb;

        $this->seedFailedAttempts(6);

        $first = new LoginSecurityHandler();
        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';
        $this->assertFalse($first->maybeBlockAppPasswordAuth(true));

        // Age the blocked row so it is close to falling out of the window.
        $staleDate = date('Y-m-d H:i:s', current_time('timestamp') - 20 * 60);
        $wpdb->update(
            "{$wpdb->prefix}fls_auth_logs",
            ['created_at' => $staleDate],
            ['id' => $this->blockedRow()->id]
        );

        $second = new LoginSecurityHandler();
        $this->assertFalse($second->maybeBlockAppPasswordAuth(true));

        $this->assertNotSame(
            $staleDate,
            $this->blockedRow()->created_at,
            'created_at should be refreshed so the lockout slides'
        );
    }

    /**
     * logBlockedAuth() looked back a fixed 1 hour while checkLoginAttempt() uses
     * login_try_timing (30 minutes by default). A blocked row that had already expired
     * was therefore still visible to logBlockedAuth(), which bumped that stale row
     * instead of recording the new lockout - losing the log entry and the notification.
     */
    public function testAnExpiredBlockedRowIsNotRevivedByANewLockout()
    {
        global $wpdb;

        // A blocked row from 45 minutes ago: outside the 30 minute window, inside 1 hour.
        $staleDate = date('Y-m-d H:i:s', current_time('timestamp') - 45 * 60);
        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'admin',
            'ip'         => Helper::getIp(),
            'status'     => 'blocked',
            'error_code' => 'blocked',
            'media'      => 'web',
            'count'      => 7,
            'created_at' => $staleDate,
            'updated_at' => $staleDate,
        ]);

        $staleId = (int)$wpdb->insert_id;

        $this->seedFailedAttempts(6);

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';
        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));

        $stale = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE id = {$staleId}");
        $this->assertSame(7, (int)$stale->count, 'The expired block must be left alone');

        $fresh = $wpdb->get_row(
            "SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `status` = 'blocked' AND id != {$staleId}"
        );
        $this->assertNotNull($fresh, 'The new lockout must be recorded as its own entry');
        $this->assertSame(1, (int)$fresh->count);
        $this->assertSame('app_password', $fresh->media);
    }

    private function seedAccountFailures($userId, $count, $ipPrefix = '203.0.113.')
    {
        global $wpdb;

        for ($i = 0; $i < $count; $i++) {
            $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
                'username'   => 'site_admin',
                'user_id'    => $userId,
                // A different source each time: this is what the IP limit cannot see.
                'ip'         => $ipPrefix . (($i % 200) + 1),
                'status'     => 'failed',
                'media'      => 'web',
                'count'      => 1,
                'created_at' => current_time('mysql'),
                'updated_at' => current_time('mysql'),
            ]);
        }
    }

    private function seedSuccessFrom($userId, $ip)
    {
        global $wpdb;

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", [
            'username'   => 'site_admin',
            'user_id'    => $userId,
            'ip'         => $ip,
            'status'     => 'success',
            'media'      => 'web',
            'count'      => 1,
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql'),
        ]);
    }

    public function testNoChallengeForAnAccountThatIsNotUnderAttack()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->seedAccountFailures($user->ID, 4);

        $this->assertFalse($this->handler->maybeRequireLoginChallenge(false, $user));
    }

    /**
     * Default limit is 5, so the account threshold is 15 spread across any number of IPs.
     */
    public function testChallengeIsRaisedOnceAccountFailuresCrossTheThreshold()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->seedAccountFailures($user->ID, 15);

        $this->assertTrue($this->handler->maybeRequireLoginChallenge(false, $user));
    }

    /**
     * The whole point of counting per account: none of these IPs individually comes
     * close to the per IP limit, so the existing block never fires.
     */
    public function testFailuresAreCountedAcrossManyDistinctIps()
    {
        global $wpdb;

        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->seedAccountFailures($user->ID, 15);

        $maxPerIp = (int)$wpdb->get_var(
            "SELECT MAX(c) FROM (SELECT COUNT(*) AS c FROM {$wpdb->prefix}fls_auth_logs GROUP BY ip) t"
        );

        $this->assertSame(1, $maxPerIp, 'No single IP is anywhere near the IP limit');
        $this->assertTrue($this->handler->maybeRequireLoginChallenge(false, $user));
    }

    /**
     * Without this the owner would be challenged on every login for as long as someone
     * kept guessing - which is the lockout-as-a-weapon problem all over again.
     */
    public function testAnIpTheUserHasLoggedInFromBeforeIsNotChallenged()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->seedAccountFailures($user->ID, 40);
        $this->seedSuccessFrom($user->ID, Helper::getIp());

        $this->assertTrue($this->handler->isTrustedIpForUser($user));
        $this->assertFalse($this->handler->maybeRequireLoginChallenge(false, $user));
    }

    public function testTrustIsPerUserNotPerIp()
    {
        $victim = $this->factory->user->create_and_get(['role' => 'administrator']);
        $other = $this->factory->user->create_and_get(['role' => 'subscriber']);

        // Someone else signing in from this IP must not vouch for the victim's account.
        $this->seedSuccessFrom($other->ID, Helper::getIp());
        $this->seedAccountFailures($victim->ID, 15);

        $this->assertFalse($this->handler->isTrustedIpForUser($victim));
        $this->assertTrue($this->handler->maybeRequireLoginChallenge(false, $victim));
    }

    public function testAccountThresholdIsFilterable()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->seedAccountFailures($user->ID, 6);
        $this->assertFalse($this->handler->maybeRequireLoginChallenge(false, $user));

        $filter = function () {
            return 6;
        };

        add_filter('fluent_auth/account_attempt_limit', $filter);
        $result = $this->handler->maybeRequireLoginChallenge(false, $user);
        remove_filter('fluent_auth/account_attempt_limit', $filter);

        $this->assertTrue($result);
    }

    public function testChallengeIsSkippedWhenTheAttemptLimitIsDisabled()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $settings = Helper::getAuthSettings();
        $settings['login_try_limit'] = 0;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->seedAccountFailures($user->ID, 50);

        $this->assertFalse($this->handler->maybeRequireLoginChallenge(false, $user));
    }

    // ------------------------------------------------------- login security always on

    /**
     * There is deliberately no setting for this. Every protection here reads the rows
     * the log writes, so an off switch would just be a way to silently disable the
     * plugin - and the old `enable_auth_logs` one did nothing anyway, because it
     * compared the string 'no' as a boolean.
     */
    public function testLoginSecurityIsOnAndCannotBeSwitchedOffFromSettings()
    {
        $settings = Helper::getAuthSettings();

        $this->assertArrayNotHasKey('enable_auth_logs', $settings);
        $this->assertTrue(Helper::isLoginSecurityEnabled());

        // Even an option left over from an older version must not turn it off.
        $settings['enable_auth_logs'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->assertTrue(Helper::isLoginSecurityEnabled());
    }

    public function testAStaleDisabledOptionStillLogsAndEnforces()
    {
        $settings = Helper::getAuthSettings();
        $settings['enable_auth_logs'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->handler->logFailedAuth('admin', new \WP_Error('incorrect_password', 'nope'));
        $this->assertSame(1, $this->countRows('failed'));

        $this->seedFailedAttempts(5);

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));
    }

    public function testCodeCanStillOptOutThroughTheFilter()
    {
        add_filter('fluent_auth/login_security_enabled', '__return_false');

        try {
            $this->assertFalse(Helper::isLoginSecurityEnabled());

            $this->handler->logFailedAuth('admin', new \WP_Error('incorrect_password', 'nope'));
            $this->assertSame(0, $this->countRows('failed'));

            $this->seedFailedAttempts(50);

            $_SERVER['PHP_AUTH_USER'] = 'admin';
            $_SERVER['PHP_AUTH_PW'] = 'wrong password';

            $this->assertTrue((new LoginSecurityHandler())->maybeBlockAppPasswordAuth(true));

            $user = $this->factory->user->create_and_get(['role' => 'administrator']);
            $this->seedAccountFailures($user->ID, 50);
            $this->assertFalse($this->handler->maybeRequireLoginChallenge(false, $user));
        } finally {
            remove_filter('fluent_auth/login_security_enabled', '__return_false');
        }
    }

    // --------------------------------------------------------------- attempt boundary

    public function testTheConfiguredLimitIsTheActualNumberOfAllowedFailures()
    {
        // Limit is 5, so 4 previous failures still leave one attempt.
        $this->seedFailedAttempts(4);

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->assertTrue($this->handler->maybeBlockAppPasswordAuth(true));
    }

    public function testTheAttemptAfterTheLimitIsBlocked()
    {
        // Used to allow a 6th: the test was `$limit >= $count`.
        $this->seedFailedAttempts(5);

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));
    }

    // ------------------------------------------------------ emailed token exemption

    /**
     * A magic link or 2FA code redeemed from the user's inbox is not a password guess.
     * Without this a locked out admin has no way back in until the window expires.
     */
    public function testATokenVerifiedLoginIsNotStoppedByTheBlock()
    {
        $this->seedFailedAttempts(20);

        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        // Control: an ordinary login from this IP is blocked.
        $blocked = $this->handler->maybeCheckLoginAttempts($user, $user->user_login, 'pw');
        $this->assertWpErrorWithCode($blocked, 'login_error');

        Helper::setTokenVerifiedLogin(true);
        $allowed = (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw');
        Helper::setTokenVerifiedLogin(false);

        $this->assertSame($user, $allowed);
    }

    /**
     * The exemption must skip the block only. If it skipped the rest of the method a
     * magic link would become a way around two factor authentication.
     */
    public function testATokenVerifiedLoginStillRunsTheTwoFactorHook()
    {
        $this->seedFailedAttempts(20);

        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $fired = false;
        $spy = function () use (&$fired) {
            $fired = true;
        };

        add_action('fluent_auth/login_attempts_checked', $spy);
        Helper::setTokenVerifiedLogin(true);
        (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw');
        Helper::setTokenVerifiedLogin(false);
        remove_action('fluent_auth/login_attempts_checked', $spy);

        $this->assertTrue($fired);
    }

    public function testTheTokenExemptionIsClearedByResetStatics()
    {
        Helper::setTokenVerifiedLogin(true);
        $this->assertTrue(Helper::isTokenVerifiedLogin());

        Helper::resetStatics();

        $this->assertFalse(Helper::isTokenVerifiedLogin());
    }

    public function testHooksAreRegistered()
    {
        $this->handler->register();

        $this->assertNotFalse(
            has_filter('wp_is_application_passwords_available', [$this->handler, 'maybeBlockAppPasswordAuth'])
        );
        $this->assertNotFalse(
            has_action('application_password_failed_authentication', [$this->handler, 'logFailedAppPasswordAuth'])
        );
    }

    // ------------------------------------------------------------- IP allow / block

    /**
     * The lists are checked at the same choke point the attempt limit uses, so these pin
     * down that both login routes honour them - and, for the allow list, that it changes
     * only whether the attempt is counted.
     *
     * A public REMOTE_ADDR is set first: the allow list refuses to apply while the site's
     * addresses are ambiguous, and the test suite's default loopback address is exactly
     * that case.
     */
    private function fromPublicAddress()
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.20';
        Helper::resetStatics();

        return '198.51.100.20';
    }

    public function testAnAllowedAddressIsNotLockedOutByTheAttemptLimit()
    {
        $ip = $this->fromPublicAddress();
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->seedFailedAttempts(20);

        // Control: without the allow list this address is well past the limit.
        $this->assertWpErrorWithCode(
            $this->handler->maybeCheckLoginAttempts($user, $user->user_login, 'pw'),
            'login_error'
        );

        \FluentAuth\App\Services\IpRules::save(['allow' => [$ip], 'block' => []]);

        $this->assertSame(
            $user,
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw')
        );
    }

    public function testTheAllowListReachesTheApplicationPasswordPathToo()
    {
        $ip = $this->fromPublicAddress();

        $this->seedFailedAttempts(20);

        $_SERVER['PHP_AUTH_USER'] = 'admin';
        $_SERVER['PHP_AUTH_PW'] = 'wrong password';

        $this->assertFalse($this->handler->maybeBlockAppPasswordAuth(true));

        \FluentAuth\App\Services\IpRules::save(['allow' => [$ip], 'block' => []]);

        $this->assertTrue((new LoginSecurityHandler())->maybeBlockAppPasswordAuth(true));
    }

    /**
     * Blocks an address the way an administrator would: from their own, which is a
     * different one - the list refuses to store a rule covering whoever is saving it.
     *
     * @param string $range
     * @return void
     */
    private function blockFromElsewhere($range)
    {
        $_SERVER['REMOTE_ADDR'] = '198.51.100.20';
        Helper::resetStatics();

        $saved = \FluentAuth\App\Services\IpRules::save(['allow' => [], 'block' => [$range]]);

        $this->assertIsArray($saved, 'the block list should have saved');
    }

    /**
     * @param string $ip
     * @return void
     */
    private function arriveFrom($ip)
    {
        $_SERVER['REMOTE_ADDR'] = $ip;
        Helper::resetStatics();
    }

    public function testABlockedAddressIsRefusedEvenWithNoFailuresAtAll()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->blockFromElsewhere('45.148.10.0/24');
        $this->arriveFrom('45.148.10.72');

        $this->assertEquals(0, $this->countRows('failed'));

        $this->assertWpErrorWithCode(
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw'),
            'login_error'
        );
    }

    /**
     * The block list is not part of the attempt limit, so switching that off must not
     * switch this off with it.
     */
    public function testABlockedAddressIsRefusedEvenWhenTheAttemptLimitIsDisabled()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->blockFromElsewhere('45.148.10.72');

        $settings = get_option('__fls_auth_settings');
        $settings['login_try_limit'] = 0;
        $settings['login_try_timing'] = 0;
        update_option('__fls_auth_settings', $settings);

        $this->arriveFrom('45.148.10.72');

        $this->assertWpErrorWithCode(
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw'),
            'login_error'
        );
    }

    public function testAnAddressOutsideTheBlockedRangeIsUntouched()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->blockFromElsewhere('45.148.10.0/24');
        $this->arriveFrom('45.148.11.72');

        $this->assertSame(
            $user,
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw')
        );
    }

    // ------------------------------------------------ restricting a role by address

    /**
     * @param string $role
     * @return \WP_User
     */
    private function restrictRoleToOfficeAddress($role = 'administrator')
    {
        $this->assertFalse(
            defined('FLUENT_AUTH_DISABLE_IP_RESTRICTION'),
            'the wp-config escape hatch leaked from an earlier test, so this proves nothing'
        );

        $_SERVER['REMOTE_ADDR'] = '198.51.100.20';
        Helper::resetStatics();

        $saved = \FluentAuth\App\Services\IpRules::save([
            'allow'            => ['198.51.100.20'],
            'block'            => [],
            'restricted_roles' => [$role]
        ]);

        $this->assertIsArray($saved, 'the restriction should have saved');

        return $this->factory->user->create_and_get(['role' => $role]);
    }

    public function testARestrictedRoleIsRefusedFromAnywhereElse()
    {
        $admin = $this->restrictRoleToOfficeAddress();

        // From the listed address it is an ordinary login.
        $this->assertSame(
            $admin,
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($admin, $admin->user_login, 'pw')
        );

        $this->arriveFrom('45.148.10.72');

        $this->assertWpErrorWithCode(
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($admin, $admin->user_login, 'pw'),
            'login_error'
        );
        $this->assertEquals(1, $this->countRows('blocked'));
    }

    public function testAnUnrestrictedRoleSignsInFromAnywhere()
    {
        $this->restrictRoleToOfficeAddress('administrator');
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $this->arriveFrom('45.148.10.72');

        $this->assertSame(
            $subscriber,
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($subscriber, $subscriber->user_login, 'pw')
        );
    }

    /**
     * The exemption that lets a locked out administrator back in with a magic link must not
     * also be a way around "administrators may only sign in from the office".
     */
    public function testAMagicLinkDoesNotGetRoundTheAddressRestriction()
    {
        $admin = $this->restrictRoleToOfficeAddress();

        $this->arriveFrom('45.148.10.72');

        Helper::setTokenVerifiedLogin(true);

        $result = (new LoginSecurityHandler())->maybeCheckLoginAttempts($admin, $admin->user_login, 'pw');

        Helper::setTokenVerifiedLogin(false);

        $this->assertWpErrorWithCode($result, 'login_error');
    }

    /**
     * A provider vouching for who somebody is says nothing about where they are, and social
     * logins never reach the authenticate chain.
     */
    public function testASocialLoginDoesNotGetRoundTheAddressRestrictionEither()
    {
        $admin = $this->restrictRoleToOfficeAddress();
        $handler = new LoginSecurityHandler();

        $this->assertTrue($handler->maybeDenyRestrictedLocation(true, $admin, 'google'));

        $this->arriveFrom('45.148.10.72');

        $this->assertWpErrorWithCode(
            $handler->maybeDenyRestrictedLocation(true, $admin, 'google'),
            'login_error'
        );

        // Without a provider AuthService only understands a plain false as a refusal.
        $this->assertFalse($handler->maybeDenyRestrictedLocation(true, $admin, ''));
    }

    public function testTheRestrictionReachesApplicationPasswordsToo()
    {
        $admin = $this->restrictRoleToOfficeAddress();

        $_SERVER['PHP_AUTH_USER'] = $admin->user_login;
        $_SERVER['PHP_AUTH_PW'] = 'an application password';

        $this->assertTrue((new LoginSecurityHandler())->maybeBlockAppPasswordAuth(true));

        $this->arriveFrom('45.148.10.72');

        $this->assertFalse((new LoginSecurityHandler())->maybeBlockAppPasswordAuth(true));
    }


    /**
     * Refusing the login must not skip the record: the dashboard's view of who is
     * attacking the site is built entirely out of these rows.
     */
    public function testARefusedAttemptFromABlockedAddressIsStillLogged()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->blockFromElsewhere('45.148.10.72');
        $this->arriveFrom('45.148.10.72');

        (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw');

        $this->assertEquals(1, $this->countRows('blocked'));
    }

    // ----------------------------------------- what a blocked address is actually told

    /**
     * The message that stops the support ticket.
     *
     * Somebody typing the right password into a site that refuses them is owed more than
     * "not permitted": which address is being refused, and - if they run the place - how to
     * get back in without us.
     */
    public function testAnAdministratorWithTheRightPasswordIsToldTheAddressAndTheWayBackIn()
    {
        $admin = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->blockFromElsewhere('45.148.10.0/24');
        $this->arriveFrom('45.148.10.72');

        $error = (new LoginSecurityHandler())->maybeCheckLoginAttempts($admin, $admin->user_login, 'pw');

        $this->assertWpErrorWithCode($error, 'login_error');

        $message = $error->get_error_message();

        $this->assertStringContainsString('45.148.10.72', $message);
        $this->assertStringContainsString('FLUENT_AUTH_DISABLE_IP_RESTRICTION', $message);
    }

    /**
     * The constant is only useful to somebody who can edit wp-config.php, and telling a
     * subscriber to go and do that is how a support ticket becomes two support tickets.
     */
    public function testAnOrdinaryUserIsPointedAtTheAdministratorInstead()
    {
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $this->blockFromElsewhere('45.148.10.0/24');
        $this->arriveFrom('45.148.10.72');

        $error = (new LoginSecurityHandler())->maybeCheckLoginAttempts($subscriber, $subscriber->user_login, 'pw');

        $message = $error->get_error_message();

        $this->assertStringContainsString('45.148.10.72', $message);
        $this->assertStringNotContainsString('FLUENT_AUTH_DISABLE_IP_RESTRICTION', $message);
        $this->assertStringContainsString('contact', $message);
    }

    /**
     * The explanation is earned by proving you hold the account. Without that, naming the
     * rule only tells whoever is guessing which network to move to next.
     */
    public function testAWrongPasswordIsToldNothingItCouldNotGuess()
    {
        $this->blockFromElsewhere('45.148.10.0/24');
        $this->arriveFrom('45.148.10.72');

        $error = (new LoginSecurityHandler())->maybeCheckLoginAttempts(
            new \WP_Error('incorrect_password', 'nope'),
            'admin',
            'pw'
        );

        $message = $error->get_error_message();

        $this->assertStringNotContainsString('45.148.10.72', $message);
        $this->assertStringNotContainsString('FLUENT_AUTH_DISABLE_IP_RESTRICTION', $message);
    }

    /**
     * The log is where an administrator who is not locked out goes to find out why somebody
     * else is, so it names the rule rather than saying "blocked".
     */
    public function testTheLogNamesTheRuleThatRefusedTheLogin()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->blockFromElsewhere('45.148.10.0/24');
        $this->arriveFrom('45.148.10.72');

        (new LoginSecurityHandler())->maybeCheckLoginAttempts($user, $user->user_login, 'pw');

        $this->assertEquals('Blocked by IP rule 45.148.10.0/24', $this->blockedRow()->description);
    }

    /**
     * The wp-config escape hatch, the way back in when the list is wrong and nobody can log
     * in to change it.
     *
     * KEEP THIS LAST. A constant cannot be undefined, so from here on the restriction is
     * switched off for everything that runs afterwards in this process. Running it in a
     * separate process is not the answer either: the child runs wpTearDownAfterClass on its
     * way out, which drops the log tables, and DDL does not roll back - the parent is left
     * without them. Anything relying on the restriction asserts the constant is absent
     * first, so a leak fails loudly rather than passing quietly.
     */
    public function testTheRestrictionCanBeSwitchedOffFromWpConfig()
    {
        $admin = $this->restrictRoleToOfficeAddress();

        // Appended, not saved over the top: save() replaces both lists and the roles with it.
        $this->assertIsArray(\FluentAuth\App\Services\IpRules::add('block', '45.148.10.0/24'));

        $this->arriveFrom('45.148.10.72');

        $this->assertTrue(\FluentAuth\App\Services\IpRules::deniesSignIn($admin));
        $this->assertTrue(\FluentAuth\App\Services\IpRules::isBlocked('45.148.10.72'));

        define('FLUENT_AUTH_DISABLE_IP_RESTRICTION', true);

        $this->assertFalse(\FluentAuth\App\Services\IpRules::deniesSignIn($admin));

        /*
         * The half that was missing: the escape hatch used to stand down the role
         * restriction only, so an administrator who had blocked their own network had
         * nothing to edit wp-config.php *for*.
         */
        $this->assertFalse(\FluentAuth\App\Services\IpRules::isBlocked('45.148.10.72'));

        $this->assertSame(
            $admin,
            (new LoginSecurityHandler())->maybeCheckLoginAttempts($admin, $admin->user_login, 'pw')
        );

        /*
         * And the social path, which asks a different function entirely - it never enters
         * the authenticate chain. An escape hatch that reached one way in and not the other
         * would be an administrator editing wp-config.php and still being turned away.
         */
        $this->assertTrue(
            (new LoginSecurityHandler())->maybeDenyRestrictedLocation(true, $admin, 'google')
        );
    }

    /* ------------------------------------------- sign ins nothing else can see */

    /**
     * A management dashboard, a community invitation, a checkout that signs the customer
     * in: all of them call wp_set_auth_cookie() directly, none of them reaches the
     * `authenticate` chain, and until now none of them appeared in the log at all. The
     * owner could see the plugin updates a dashboard had performed but not the sign in
     * that performed them - which is exactly the question asked when something looks
     * wrong.
     */
    public function test_a_sign_in_made_by_a_plugin_is_recorded()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
        $this->handler->logDirectLogins();

        $row = $this->lastRowFor($user->ID);

        $this->assertNotNull($row, 'a sign in that fires no wp_login still happened');
        $this->assertSame('success', $row->status);
        $this->assertSame('direct_login', $row->media);
        $this->assertSame(Helper::getIp(), $row->ip);
        $this->assertSame('Programmatic login', Helper::getLoginMediaLabel($row->media));
    }

    /**
     * An ordinary sign in reaches both hooks - core mints the cookie and then fires
     * `wp_login` - and must be written once, by the one that knows what kind it was.
     */
    public function test_an_ordinary_sign_in_is_not_recorded_twice()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        // The front door: the `authenticate` chain hands back a user, then the cookie.
        $this->handler->noteChainAuthenticated($user);
        $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
        $this->handler->logAuthSuccess($user->user_login, $user);
        $this->handler->logDirectLogins();

        $this->assertSame(1, $this->countRowsFor($user->ID));
        $this->assertSame('web', $this->lastRowFor($user->ID)->media);
    }

    /**
     * The case this whole path was written for. MainWP mints its own cookie and then
     * fires `wp_login` by hand, which used to be enough to have it written down as a
     * login form somebody had filled in. Nothing came through the `authenticate` chain,
     * so it is named for what it is.
     */
    public function test_a_plugin_that_fires_wp_login_itself_is_still_a_programmatic_login()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
        $this->handler->logAuthSuccess($user->user_login, $user);
        $this->handler->logDirectLogins();

        $this->assertSame(1, $this->countRowsFor($user->ID));
        $this->assertSame('direct_login', $this->lastRowFor($user->ID)->media);
    }

    /**
     * And it collapses like any other, rather than leaving a row per sync because the
     * dashboard happened to announce itself.
     */
    public function test_repeated_sign_ins_that_fire_wp_login_collapse_too()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        foreach (range(1, 3) as $ignored) {
            LoginSecurityHandler::resetRequestState();
            $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
            $this->handler->logAuthSuccess($user->user_login, $user);
            $this->handler->logDirectLogins();
        }

        $this->assertSame(1, $this->countRowsFor($user->ID));
        $this->assertSame(3, (int)$this->lastRowFor($user->ID)->count);
    }

    /**
     * Our own passwordless flows mint the cookie themselves and so look exactly like
     * somebody else's plugin doing it. They own up first, and are then written down
     * under the route they actually came in by - a Google sign in reads as Google, not
     * as an unexplained programmatic login by a plugin the owner cannot name.
     */
    public function test_our_own_passwordless_login_is_not_blamed_on_another_plugin()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        Helper::setLoginMedia('google');
        LoginSecurityHandler::noteOwnLogin($user->ID);

        $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
        $this->handler->logAuthSuccess($user->user_login, $user);
        $this->handler->logDirectLogins();

        $this->assertSame(1, $this->countRowsFor($user->ID));
        $this->assertSame('google', $this->lastRowFor($user->ID)->media);
    }

    /**
     * The auto login after signup fires no `wp_login` at all, so the only thing that
     * could speak for it is the declaration. Without one it left the owner a row saying
     * another plugin had signed their new member in.
     */
    public function test_a_declared_login_that_fires_no_wp_login_leaves_no_programmatic_row()
    {
        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);

        LoginSecurityHandler::noteOwnLogin($user->ID);

        $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
        $this->handler->logDirectLogins();

        $this->assertSame(0, $this->countRowsFor($user->ID));
    }

    /**
     * `wp_login` is documented as passing the user, and core always does - but a plugin
     * firing it by hand may pass the login alone. MainWP does, on the branch that opens
     * wp-admin, and a required second argument made that a fatal error in its request.
     */
    public function test_a_wp_login_fired_with_only_a_username_is_survived()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        do_action('wp_login', $user->user_login);

        $this->assertSame(1, $this->countRowsFor($user->ID));
    }

    /**
     * A dashboard syncing every few minutes would otherwise bury everything else in the
     * log the owner actually reads. One row, carrying a count, says the same thing.
     */
    public function test_repeated_plugin_sign_ins_collapse_into_one_row()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        foreach (range(1, 3) as $ignored) {
            LoginSecurityHandler::resetRequestState();
            $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
            $this->handler->logDirectLogins();
        }

        $this->assertSame(1, $this->countRowsFor($user->ID));
        $this->assertSame(3, (int)$this->lastRowFor($user->ID)->count);
    }

    /**
     * A cookie re-issued to whoever is already here - after a password change, or the
     * recovery sweep - is not a sign in and must not read as one.
     */
    public function test_a_cookie_reissued_to_the_person_already_here_is_not_a_sign_in()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        // What core does on the way in when the request carries a valid cookie.
        do_action('auth_cookie_valid', [], $user);

        $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
        $this->handler->logDirectLogins();

        $this->assertSame(0, $this->countRowsFor($user->ID));
    }

    /**
     * No mail, whatever the success-email setting says. These arrive on a timer, and a
     * notification per sync is the noise this whole change exists to remove.
     */
    public function test_a_plugin_sign_in_mails_nobody()
    {
        $settings = Helper::getAuthSettings();
        $settings['notification_user_roles'] = ['administrator'];
        $settings['notification_email'] = 'owner@example.org';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $user = $this->factory->user->create_and_get(['role' => 'administrator']);

        $mails = [];
        $spy = function ($atts) use (&$mails) {
            $mails[] = $atts;
            return $atts;
        };
        add_filter('wp_mail', $spy);

        try {
            $this->handler->noteDirectLogin('cookie', 0, 0, $user->ID);
            $this->handler->logDirectLogins();

            $this->assertSame([], $mails, 'a sync every few minutes must not mail every few minutes');

            // The same settings, a person signing in: that one is still announced.
            $this->handler->logAuthSuccess($user->user_login, $user);
        } finally {
            remove_filter('wp_mail', $spy);
        }

        $this->assertCount(1, $mails, 'precondition: the success email is switched on');
    }

    private function lastRowFor($userId)
    {
        return flsDb()->table('fls_auth_logs')
            ->where('user_id', $userId)
            ->orderBy('id', 'DESC')
            ->first();
    }

    private function countRowsFor($userId)
    {
        return (int)flsDb()->table('fls_auth_logs')
            ->where('user_id', $userId)
            ->count();
    }
}
