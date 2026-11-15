<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\SessionLengthHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Http\Controllers\SettingsController;

class PersistentLoginTest extends BaseTestCase
{
    private $user;
    private $handler;
    private $server;
    private $cookies;

    public function setUp(): void
    {
        parent::setUp();
        TwoFaHandler::resetRequestState();
        $this->server = $_SERVER;
        $this->cookies = $_COOKIE;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        wp_set_current_user(0);
        $this->user = $this->factory->user->create_and_get(['role' => 'subscriber']);
        $this->handler = $this->newHandler();
        $this->settings();
    }

    private function newHandler()
    {
        // CLI PHPUnit has already printed progress. Keep headers writable for each
        // simulated request; real HTTP specs verify actual headers separately.
        return new class extends SessionLengthHandler {
            protected function headersSent() { return false; }
        };
    }

    public function tearDown(): void
    {
        $_SERVER = $this->server;
        $_COOKIE = $this->cookies;
        wp_set_current_user(0);
        TwoFaHandler::resetRequestState();
        Helper::resetStatics();
        parent::tearDown();
    }

    private function settings($extra = [])
    {
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), [
            'persistent_login' => 'yes', 'persistent_login_days' => 30,
            'persistent_login_scope' => 'selected', 'persistent_login_roles' => ['subscriber'],
            'persistent_login_renew' => 'yes'
        ], $extra));
        Helper::resetStatics();
    }

    public function testEligibleUncheckedLoginGetsConfiguredDuration()
    {
        wp_set_auth_cookie($this->user->ID, false);
        $sessions = \WP_Session_Tokens::get_instance($this->user->ID)->get_all();
        $this->assertCount(1, $sessions);
        $session = reset($sessions);
        $this->assertEqualsWithDelta(30 * DAY_IN_SECONDS, $session['expiration'] - time(), 3);
        $this->assertSame(get_current_blog_id(), $session['fls_persistent_site']);
    }

    /** @dataProvider durations */
    public function testRolePolicyAppliesToEitherRememberChoice($days, $remember)
    {
        $this->settings(['persistent_login_days' => $days]);
        $this->assertSame($days * DAY_IN_SECONDS,
            $this->handler->filterExpiration(99999999, $this->user->ID, $remember));
    }

    public static function durations()
    {
        return [[30, false], [30, true], [90, false], [90, true], [180, false], [180, true]];
    }

    public function testDisabledAndUnselectedPreserveMergedGlobalSettings()
    {
        foreach ([['persistent_login' => 'no'], ['persistent_login_roles' => []],
            ['persistent_login_roles' => ['editor']]] as $extra) {
            $this->settings(array_merge(['remember_days' => 90], $extra));
            $this->assertSame(90 * DAY_IN_SECONDS, $this->handler->filterExpiration(14 * DAY_IN_SECONDS, $this->user->ID, true));
        }
        $this->settings(['persistent_login_scope' => 'all', 'persistent_login_roles' => []]);
        $this->assertSame(30 * DAY_IN_SECONDS, $this->handler->filterExpiration(1, $this->user->ID, false));
        $this->user->add_role('editor');
        $this->settings(['persistent_login_roles' => ['editor']]);
        $this->assertSame(30 * DAY_IN_SECONDS, $this->handler->filterExpiration(1, $this->user->ID, false));
    }

    private function arrived($sessionExtra = [])
    {
        $manager = \WP_Session_Tokens::get_instance($this->user->ID);
        $token = $manager->create(time() + DAY_IN_SECONDS);
        $session = array_merge($manager->get($token), [
            'fls_persistent_site' => get_current_blog_id(), 'fls_renewed' => time() - 2 * DAY_IN_SECONDS
        ], $sessionExtra);
        $manager->update($token, $session);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($this->user->ID, time() + DAY_IN_SECONDS, 'logged_in', $token);
        wp_set_current_user($this->user->ID);
        $this->handler->noteAuthenticated(wp_parse_auth_cookie('', 'logged_in'), $this->user);
        return [$manager, $token];
    }

    public function testRenewalExtendsSameTokenOnceAndPreservesMetadata()
    {
        list($manager, $token) = $this->arrived(['custom_metadata' => 'keep']);
        $this->handler->renew();
        $session = $manager->get($token);
        $this->assertEqualsWithDelta(time() + 30 * DAY_IN_SECONDS, $session['expiration'], 3);
        $this->assertSame('keep', $session['custom_metadata']);
        $this->assertCount(1, $manager->get_all());
        $queries = get_num_queries();
        $this->handler->renew();
        $this->assertSame($queries, get_num_queries(), 'Do not renew twice in one request.');
    }

    /** @dataProvider skippedSessions */
    public function testUnmarkedRecentAndOtherSiteSessionsDoNotRenew($extra)
    {
        list($manager, $token) = $this->arrived($extra);
        $before = $manager->get($token);
        $this->handler->renew();
        $this->assertSame($before, $manager->get($token));
    }

    public static function skippedSessions()
    {
        return [[['fls_persistent_site' => 0]], [['fls_renewed' => PHP_INT_MAX]], [['fls_persistent_site' => -1]]];
    }

    public function testPostAndRemovedRoleDoNotRenew()
    {
        list($manager, $token) = $this->arrived();
        $before = $manager->get($token);
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->handler->renew();
        $this->assertSame($before, $manager->get($token));
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->settings(['persistent_login_roles' => []]);
        $this->handler->renew();
        $this->assertSame($before, $manager->get($token));
    }

    public function testConcurrentRevocationCannotRecreateTheToken()
    {
        list($manager, $token) = $this->arrived();
        $interleaved = false;
        $revoke = function ($query) use (&$revoke, &$interleaved, $manager, $token) {
            global $wpdb;
            if (strpos($query, "UPDATE `{$wpdb->usermeta}`") === 0) {
                remove_filter('query', $revoke);
                $interleaved = true;
                $manager->destroy($token);
            }
            return $query;
        };
        add_filter('query', $revoke);
        try {
            $this->handler->renew();
        } finally {
            remove_filter('query', $revoke);
        }
        $this->assertTrue($interleaved, 'The revocation occurred immediately before the conditional update.');
        $this->assertFalse($manager->verify($token), 'A stale renewal must not resurrect a revoked session.');
    }

    public function testConcurrentNewLoginIsNotOverwritten()
    {
        list($manager, $token) = $this->arrived();
        $before = $manager->get($token);
        $other = '';
        $login = function ($query) use (&$login, &$other, $manager) {
            global $wpdb;
            if (strpos($query, "UPDATE `{$wpdb->usermeta}`") === 0) {
                remove_filter('query', $login);
                $other = $manager->create(time() + DAY_IN_SECONDS);
            }
            return $query;
        };
        add_filter('query', $login);
        try { $this->handler->renew(); }
        finally { remove_filter('query', $login); }
        $this->assertNotEmpty($other);
        $this->assertTrue($manager->verify($other));
        $this->assertSame($before, $manager->get($token), 'Skip renewal on a conflicting token-map change.');
    }

    public function testCaseOnlyMetadataConflictIsNotOverwritten()
    {
        list($manager, $token) = $this->arrived(['custom_metadata' => 'lowercase']);
        $change = function ($query) use (&$change, $manager, $token) {
            global $wpdb;
            if (strpos($query, "UPDATE `{$wpdb->usermeta}`") === 0) {
                remove_filter('query', $change);
                $session = $manager->get($token);
                $session['custom_metadata'] = 'LOWERCASE';
                $manager->update($token, $session);
            }
            return $query;
        };
        add_filter('query', $change);
        try { $this->handler->renew(); }
        finally { remove_filter('query', $change); }
        $this->assertSame('LOWERCASE', $manager->get($token)['custom_metadata']);
    }

    /** @dataProvider foregroundGuards */
    public function testBackgroundAndPrefetchDoNotRenew($key, $value)
    {
        list($manager, $token) = $this->arrived();
        $before = $manager->get($token);
        $_SERVER[$key] = $value;
        $this->handler->renew();
        $this->assertSame($before, $manager->get($token));
    }

    public static function foregroundGuards()
    {
        return [['HTTP_SEC_FETCH_DEST', 'empty'], ['HTTP_SEC_FETCH_DEST', 'iframe'],
            ['HTTP_PURPOSE', 'prefetch'], ['HTTP_SEC_PURPOSE', 'prefetch;prerender']];
    }

    public function testExpiredCookieAndDisabledRenewalStayUnchanged()
    {
        list($manager, $token) = $this->arrived();
        $before = $manager->get($token);
        $elements = wp_parse_auth_cookie('', 'logged_in');
        $elements['expiration'] = time() - 1;
        $this->handler->noteAuthenticated($elements, $this->user);
        $this->handler->renew();
        $this->assertSame($before, $manager->get($token));
        $this->handler->noteAuthenticated(wp_parse_auth_cookie('', 'logged_in'), $this->user);
        $this->settings(['persistent_login_renew' => 'no']);
        $this->handler->renew();
        $this->assertSame($before, $manager->get($token));
    }

    public function testRecoveryStyleReissuePreservesBaseDurationAndSessionMetadata()
    {
        TwoFaHandler::resetRequestState();
        (new TwoFaHandler())->rememberAuthenticatedUser([], $this->user);
        $this->assertSame(2 * DAY_IN_SECONDS, $this->handler->filterExpiration(2 * DAY_IN_SECONDS, $this->user->ID, false));
        $this->assertSame([], $this->handler->markSession([], $this->user->ID));
    }

    /** @dataProvider providers */
    public function testVerifiedSocialAndPasswordlessCompletionUsesThePolicy($provider)
    {
        $signedIn = \FluentAuth\App\Services\AuthService::makeLogin($this->user, $provider);
        $this->assertInstanceOf(\WP_User::class, $signedIn);
        $sessions = \WP_Session_Tokens::get_instance($this->user->ID)->get_all();
        $this->assertCount(1, $sessions);
        $session = reset($sessions);
        $this->assertEqualsWithDelta(time() + 30 * DAY_IN_SECONDS, $session['expiration'], 3);
    }

    public static function providers() { return [['google'], ['github'], ['facebook'], ['']]; }

    public function testCustomManagerDisablesOnlyRenewal()
    {
        $custom = function () { return 'Custom_Session_Manager'; };
        add_filter('session_token_manager', $custom);
        try {
            $this->assertFalse(SessionLengthHandler::supportsRenewal());
            $this->assertSame(30 * DAY_IN_SECONDS, $this->handler->filterExpiration(1, $this->user->ID, false));
            $response = SettingsController::getSettings(new \WP_REST_Request());
            $this->assertFalse($response['settings']['persistent_renewal_supported']);
        } finally {
            remove_filter('session_token_manager', $custom);
        }
    }

    /** @dataProvider invalidPolicies */
    public function testInvalidPolicyIsRejectedWithoutSaving($extra)
    {
        $before = get_option('__fls_auth_settings');
        $request = new \WP_REST_Request();
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), $extra));
        $this->assertWPError(SettingsController::updateSettings($request));
        $this->assertSame($before, get_option('__fls_auth_settings'));
    }

    public static function invalidPolicies()
    {
        return [[['persistent_login_days' => '30.5']], [['persistent_login_days' => -30]],
            [['persistent_login_days' => 365]], [['persistent_login_scope' => 'everyone']],
            [['persistent_login' => ['yes']]], [['persistent_login_renew' => true]],
            [['persistent_login_roles' => ['invented_role']]], [['persistent_login_roles' => 'subscriber']]];
    }

    public function testLegacyClientPreservesPolicyAndCannotSubmitSupportFlag()
    {
        $request = new \WP_REST_Request();
        $settings = Helper::getAuthSettings();
        foreach (array_keys($settings) as $key) {
            if (strpos($key, 'persistent_login') === 0) { unset($settings[$key]); }
        }
        $settings['persistent_renewal_supported'] = false;
        $request->set_param('settings', $settings);
        $response = SettingsController::updateSettings($request);
        $this->assertIsArray($response);
        $this->assertSame(30, $response['settings']['persistent_login_days']);
        $this->assertTrue($response['settings']['persistent_renewal_supported']);
        $this->assertArrayNotHasKey('persistent_renewal_supported', get_option('__fls_auth_settings'));
    }

    public function testExplicitEmptyFormSelectionClearsRoles()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), ['persistent_login_roles' => '']));
        $response = SettingsController::updateSettings($request);
        $this->assertSame([], $response['settings']['persistent_login_roles']);
    }

    public function testMalformedStoredPolicyFailsClosedWithoutWarnings()
    {
        foreach ([['persistent_login_days' => [30]], ['persistent_login_roles' => [['subscriber']]],
            ['persistent_login_roles' => 'subscriber']] as $extra) {
            $this->settings($extra);
            $this->assertSame(2 * DAY_IN_SECONDS, $this->handler->filterExpiration(2 * DAY_IN_SECONDS, $this->user->ID, false));
        }
    }

    public function testRecentSessionsAndGuestsDoNotWriteOnThreeRenders()
    {
        list($manager, $token) = $this->arrived(['fls_renewed' => time()]);
        $elements = wp_parse_auth_cookie('', 'logged_in');
        $writes = 0;
        $observe = function ($query) use (&$writes) {
            if (preg_match('/^(UPDATE|INSERT|DELETE)/i', $query)) { $writes++; }
            return $query;
        };
        add_filter('query', $observe);
        try {
            for ($i = 0; $i < 3; $i++) {
                $handler = $this->newHandler();
                $handler->noteAuthenticated($elements, $this->user);
                $handler->renew();
                $this->newHandler()->renew();
            }
        } finally { remove_filter('query', $observe); }
        $this->assertSame(0, $writes);
    }

    public function testRemovedSavedRoleDoesNotBlockTheNextSave()
    {
        $this->settings(['persistent_login_roles' => ['removed_role']]);
        $request = new \WP_REST_Request();
        $request->set_param('settings', Helper::getAuthSettings());
        $response = SettingsController::updateSettings($request);
        $this->assertSame([], $response['settings']['persistent_login_roles']);
    }
}
