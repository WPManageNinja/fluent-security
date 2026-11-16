<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\SessionLengthHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Http\Controllers\SettingsController;

class SessionLengthTest extends BaseTestCase
{
    private $method;
    private $cookieVeto;

    public function setUp(): void
    {
        parent::setUp();
        $this->method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : null;
        delete_option('__fls_auth_settings');
        Helper::resetStatics();
        // Core's test veto runs before our policy. Veto after it instead, without sending headers.
        remove_filter('send_auth_cookies', '__return_false');
        $this->cookieVeto = '__return_false';
        add_filter('send_auth_cookies', $this->cookieVeto, PHP_INT_MAX);
    }

    public function tearDown(): void
    {
        remove_filter('send_auth_cookies', $this->cookieVeto, PHP_INT_MAX);
        add_filter('send_auth_cookies', '__return_false');
        if ($this->method === null) {
            unset($_SERVER['REQUEST_METHOD']);
        } else {
            $_SERVER['REQUEST_METHOD'] = $this->method;
        }
        delete_option('__fls_auth_settings');
        Helper::resetStatics();
        parent::tearDown();
    }

    private function saveSettings(array $overrides)
    {
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), $overrides));
        Helper::resetStatics();
    }

    private function sessionLengthAfterSignIn($remember)
    {
        $userId = $this->factory->user->create();
        $before = time();
        wp_set_auth_cookie($userId, $remember);

        $sessions = \WP_Session_Tokens::get_instance($userId)->get_all();
        $this->assertCount(1, $sessions);

        return reset($sessions)['expiration'] - $before;
    }

    private function assertDays($days, $seconds)
    {
        $this->assertEqualsWithDelta($days * DAY_IN_SECONDS, $seconds, 5);
    }

    public function testDefaultsMatchWordPress()
    {
        $this->assertDays(2, $this->sessionLengthAfterSignIn(false));
        $this->assertDays(14, $this->sessionLengthAfterSignIn(true));
    }

    public function testDefaultsLeaveOtherFiltersAlone()
    {
        $this->assertSame(12345, (new SessionLengthHandler())->filterExpiration(12345, 1, true));
        $this->assertSame(12345, (new SessionLengthHandler())->filterExpiration(12345, 1, false));
    }

    public function testCustomLengthsApplyToNewSessions()
    {
        $this->saveSettings(['session_days' => 7, 'remember_days' => 180]);

        $this->assertDays(7, $this->sessionLengthAfterSignIn(false));
        $this->assertDays(180, $this->sessionLengthAfterSignIn(true));
    }

    public function testOwnersCanShortenBelowTheWordPressDefaults()
    {
        $this->saveSettings(['session_days' => 1, 'remember_days' => 7]);

        $this->assertDays(1, $this->sessionLengthAfterSignIn(false));
        $this->assertDays(7, $this->sessionLengthAfterSignIn(true));
    }

    public function testALongerLengthFromAnotherHookWins()
    {
        $this->saveSettings(['session_days' => 7, 'remember_days' => 30]);

        $other = function () {
            return 90 * DAY_IN_SECONDS;
        };
        add_filter('auth_cookie_expiration', $other, 5);

        $this->assertDays(90, $this->sessionLengthAfterSignIn(false));
        $this->assertDays(90, $this->sessionLengthAfterSignIn(true));

        remove_filter('auth_cookie_expiration', $other, 5);
    }

    public function testOursWinsOverAnotherHookThatIsLongerThanWordPressButShorterThanOurs()
    {
        $this->saveSettings(['remember_days' => 90]);

        $other = function () {
            return 30 * DAY_IN_SECONDS;
        };
        add_filter('auth_cookie_expiration', $other, 5);

        $this->assertDays(90, $this->sessionLengthAfterSignIn(true));

        remove_filter('auth_cookie_expiration', $other, 5);
    }

    public function testAnEmptyValueFallsBackToTheWordPressDefault()
    {
        $this->saveSettings(['session_days' => '', 'remember_days' => 'abc']);

        $this->assertSame(2, SessionLengthHandler::sessionDays());
        $this->assertSame(14, SessionLengthHandler::rememberDays());
    }

    public function testAShorterLengthFromAnotherHookLosesToTheOwnersSetting()
    {
        $this->saveSettings(['remember_days' => 30]);

        $other = function () {
            return 3 * DAY_IN_SECONDS;
        };
        add_filter('auth_cookie_expiration', $other, 5);

        $this->assertDays(30, $this->sessionLengthAfterSignIn(true));

        remove_filter('auth_cookie_expiration', $other, 5);
    }

    public function switchCases()
    {
        return [[true, []], [false, ['rememberme' => '1']]];
    }

    /** @dataProvider switchCases */
    public function testSwitchingTheSecondFactorKeepsTheRememberChoice($remember, $switchRequest)
    {
        $this->saveSettings(['totp_2fa' => 'yes', 'totp_2fa_roles' => ['subscriber']]);
        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);
        \FluentAuth\App\Services\TwoFa\TotpTwoFaMethod::activate($user, 'JBSWY3DPEHPK3PXP');

        $twoFa = new TwoFaHandler();
        $_REQUEST = [];
        $pending = $twoFa->sendAndGet2FaConfirmFormUrl($user, 'both', null, new PasskeyTwoFaMethod(), $remember);

        $_REQUEST = array_merge(['login_hash' => $pending['login_hash']], $switchRequest);
        $location = '';
        $stop = function ($url) use (&$location) {
            $location = $url;
            throw new \RuntimeException('switched');
        };
        add_filter('wp_redirect', $stop);

        try {
            $twoFa->switchMethod();
            $this->fail('precondition: the switch should redirect');
        } catch (\RuntimeException $e) {
            $this->assertSame('switched', $e->getMessage());
        } finally {
            remove_filter('wp_redirect', $stop);
            $_REQUEST = [];
        }

        parse_str((string)wp_parse_url($location, PHP_URL_QUERY), $query);
        $replacement = flsDb()->table('fls_login_hashes')->where('login_hash', $query['login_hash'])->first();

        $this->assertSame('totp', $replacement->use_type);
        $this->assertSame($remember, substr($replacement->login_hash, -5) === '-auth');
    }

    public function testStoredValuesOutOfRangeAreClampedOnRead()
    {
        $this->saveSettings(['session_days' => 0, 'remember_days' => 5000]);

        $this->assertSame(1, SessionLengthHandler::sessionDays());
        $this->assertSame(365, SessionLengthHandler::rememberDays());
    }

    public function testRememberIsNeverShorterThanANormalSession()
    {
        $this->saveSettings(['session_days' => 30, 'remember_days' => 10]);

        $this->assertSame(30, SessionLengthHandler::rememberDays());
    }

    public function testSaveCleansTheValues()
    {
        $this->saveSettings([]);

        $request = new \WP_REST_Request();
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), [
            'session_days'     => '30',
            'remember_days'    => '10',
            'remember_default' => 'false'
        ]));
        $saved = SettingsController::updateSettings($request)['settings'];

        $this->assertSame(30, $saved['session_days']);
        $this->assertSame(30, $saved['remember_days']);
        $this->assertSame('yes', $saved['remember_default']);

        $request->set_param('settings', array_merge(Helper::getAuthSettings(), [
            'session_days'     => '-4',
            'remember_days'    => '9999',
            'remember_default' => 'no'
        ]));
        $saved = SettingsController::updateSettings($request)['settings'];

        $this->assertSame(1, $saved['session_days']);
        $this->assertSame(365, $saved['remember_days']);
        $this->assertSame('no', $saved['remember_default']);
    }

    public function testSavingEmptyFieldsRestoresTheWordPressDefaults()
    {
        $this->saveSettings(['session_days' => 30, 'remember_days' => 90]);

        $request = new \WP_REST_Request();
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), [
            'session_days'  => '',
            'remember_days' => 'abc'
        ]));
        $saved = SettingsController::updateSettings($request)['settings'];

        $this->assertSame(2, $saved['session_days']);
        $this->assertSame(14, $saved['remember_days']);
    }

    private function issueLimitedCookie($userId, $supplied = '')
    {
        $token = '';
        $capture = function ($cookie, $expire, $expiration, $id, $scheme, $issued) use (&$token) {
            if (!$token) {
                $token = $issued;
            }
        };
        add_action('set_logged_in_cookie', $capture, 20, 6);
        try {
            wp_set_auth_cookie($userId, false, '', $supplied);
        } finally {
            remove_action('set_logged_in_cookie', $capture, 20);
        }
        return $token;
    }

    public function testSessionLimitDefaultsToUnlimitedOnLegacySites()
    {
        $this->assertSame(0, Helper::getAuthSettings()['session_limit'] ?? null);
        $id = $this->factory->user->create();
        for ($i = 0; $i < 3; $i++) {
            $this->issueLimitedCookie($id);
        }
        $this->assertCount(3, \WP_Session_Tokens::get_instance($id)->get_all());
    }

    public function testSessionLimitKeepsIncomingAndNewestOtherSession()
    {
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS);
        $newer = $manager->create(time() + DAY_IN_SECONDS);
        $manager->update($old, ['expiration' => time() + DAY_IN_SECONDS, 'login' => 10, 'extra' => 'preserve']);
        $manager->update($newer, ['expiration' => time() + DAY_IN_SECONDS, 'login' => 20, 'extra' => 'preserve']);
        $this->saveSettings(['session_limit' => 2]);
        $incoming = $this->issueLimitedCookie($id);
        $this->assertFalse($manager->verify($old));
        $this->assertTrue($manager->verify($newer));
        $this->assertTrue($manager->verify($incoming));
        $this->assertSame('preserve', $manager->get($newer)['extra']);
        $this->assertCount(2, $manager->get_all());
    }

    public function testSessionLimitCountsLegacyIntegersButNotExpiredSessions()
    {
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $legacy = $manager->create(time() + DAY_IN_SECONDS);
        $map = get_user_meta($id, 'session_tokens', true);
        $map[hash('sha256', $legacy)] = time() + DAY_IN_SECONDS;
        $map[hash('sha256', 'expired')] = ['expiration' => time() - 1];
        update_user_meta($id, 'session_tokens', $map);
        $this->saveSettings(['session_limit' => 1]);
        $incoming = $this->issueLimitedCookie($id);
        $this->assertFalse($manager->verify($legacy));
        $this->assertTrue($manager->verify($incoming));
        $this->assertCount(1, $manager->get_all());
    }

    public function testSessionLimitDoesNotEvictOnSaveOrExistingTokenReissue()
    {
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $first = $manager->create(time() + DAY_IN_SECONDS);
        $second = $manager->create(time() + DAY_IN_SECONDS);
        $map = get_user_meta($id, 'session_tokens', true);
        $map[hash('sha256', $first)] = time() + DAY_IN_SECONDS;
        update_user_meta($id, 'session_tokens', $map);
        $this->saveSettings(['session_limit' => 1]);
        $this->assertCount(2, $manager->get_all(), 'Saving applies at the next new sign-in');
        $manager->create(time() + DAY_IN_SECONDS); // A different token must not mark this reissue as new.
        $this->issueLimitedCookie($id, $first);
        $this->assertTrue($manager->verify($first));
        $this->assertTrue($manager->verify($second));
        $this->assertCount(3, $manager->get_all());
    }

    public function testSessionLimitRespectsCookieSuppression()
    {
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1]);
        add_filter('send_auth_cookies', '__return_false');
        try {
            $this->issueLimitedCookie($id);
            $this->assertTrue($manager->verify($old));
        } finally {
            remove_filter('send_auth_cookies', '__return_false');
        }
    }

    public function testSessionLimitCompletesAtDirectCookieIssuanceWithoutWpLogin()
    {
        $id = $this->factory->user->create(['role' => 'administrator']);
        $this->saveSettings(['session_limit' => 1]);
        $first = $this->issueLimitedCookie($id);
        $second = $this->issueLimitedCookie($id);
        $manager = \WP_Session_Tokens::get_instance($id);
        $this->assertFalse($manager->verify($first));
        $this->assertTrue($manager->verify($second));
    }

    /** @dataProvider invalidSessionLimits */
    public function testSessionLimitTreatsMalformedStoredValuesAsUnlimited($value)
    {
        $this->saveSettings(['session_limit' => $value]);
        $id = $this->factory->user->create();
        $first = $this->issueLimitedCookie($id);
        $this->issueLimitedCookie($id);
        $this->assertTrue(\WP_Session_Tokens::get_instance($id)->verify($first));
        $this->assertCount(2, \WP_Session_Tokens::get_instance($id)->get_all());
    }

    public function testSessionLimitRetriesWithoutResurrectingConcurrentRevocations()
    {
        global $wpdb;
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1]);
        $interleaved = false;
        $race = function ($sql) use (&$race, &$interleaved, $manager, $old, $wpdb) {
            if (strpos($sql, "UPDATE {$wpdb->usermeta} SET meta_value") === 0 && strpos($sql, 'BINARY meta_value') !== false) {
                remove_filter('query', $race);
                $interleaved = true;
                $manager->destroy($old);
            }
            return $sql;
        };
        add_filter('query', $race);
        try {
            $incoming = $this->issueLimitedCookie($id);
            $this->assertTrue($interleaved, 'Revocation ran between the actual database read and conditional write');
            $this->assertFalse($manager->verify($old));
            $this->assertTrue($manager->verify($incoming));
            $this->assertCount(1, $manager->get_all());
        } finally {
            remove_filter('query', $race);
        }
    }

    public function testSessionLimitHandlesCoreBeforeCookieContextArguments()
    {
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1]);
        $incoming = $manager->create(time() + DAY_IN_SECONDS);
        do_action('set_logged_in_cookie', '', 0, time() + DAY_IN_SECONDS, $id, 'logged_in', $incoming);
        apply_filters('send_auth_cookies', true); // WordPress 5.0–6.1 supplies only this argument.
        $this->assertFalse($manager->verify($old));
        $this->assertTrue($manager->verify($incoming));
    }

    public function testSessionLimitLeavesCustomManagersAloneAndReportsAvailability()
    {
        $custom = function () { return SessionLimitCustomStore::class; };
        add_filter('session_token_manager', $custom);
        try {
            $this->saveSettings(['session_limit' => 1]);
            $id = $this->factory->user->create();
            $first = $this->issueLimitedCookie($id);
            $second = $this->issueLimitedCookie($id);
            $this->assertTrue(\WP_Session_Tokens::get_instance($id)->verify($first));
            $this->assertTrue(\WP_Session_Tokens::get_instance($id)->verify($second));
            $this->assertFalse(SettingsController::getSettings(new \WP_REST_Request())['settings']['session_limit_supported'] ?? null);
        } finally {
            remove_filter('session_token_manager', $custom);
        }
    }

    public function testSessionLimitDoesNotResurrectAnIncomingLoginEvictedByAnotherLogin()
    {
        global $wpdb;
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $manager->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1]);
        $winner = '';
        $race = function ($sql) use (&$race, &$winner, $id, $wpdb) {
            if (strpos($sql, "UPDATE {$wpdb->usermeta} SET meta_value") === 0 && strpos($sql, 'BINARY meta_value') !== false) {
                remove_filter('query', $race);
                $winner = $this->issueLimitedCookie($id);
            }
            return $sql;
        };
        add_filter('query', $race);
        try {
            $loser = $this->issueLimitedCookie($id);
            $this->assertNotSame('', $winner, 'A second completed login interleaved at the actual conditional write');
            $this->assertFalse($manager->verify($loser));
            $this->assertTrue($manager->verify($winner));
            $this->assertCount(1, $manager->get_all());
        } finally { remove_filter('query', $race); }
    }

    /** @dataProvider invalidSessionLimits */
    public function testSessionLimitRejectsInvalidSettingsWithoutSaving($value)
    {
        $before = get_option('__fls_auth_settings');
        $request = new \WP_REST_Request();
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), ['session_limit' => $value]));
        $this->assertWPError(SettingsController::updateSettings($request));
        $this->assertSame($before, get_option('__fls_auth_settings'));
    }

    public function invalidSessionLimits()
    {
        return [[-1], [101], [1.5], ['1e1'], ['abc'], [[]], [true]];
    }

    public function testSessionLimitWaitsForTheRemainingSecondFactor()
    {
        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);
        $old = \WP_Session_Tokens::get_instance($user->ID)->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1, 'email2fa' => 'yes', 'email2fa_roles' => ['subscriber']]);
        $result = \FluentAuth\App\Services\AuthService::makeLogin($user);
        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
        $this->assertTrue(\WP_Session_Tokens::get_instance($user->ID)->verify($old));
    }

    public function testSessionLimitAppliesAtTheVerifiedProviderCompletionBoundary()
    {
        $user = $this->factory->user->create_and_get();
        $this->saveSettings(['session_limit' => 1]);
        $old = $this->issueLimitedCookie($user->ID);
        $this->assertInstanceOf(\WP_User::class, \FluentAuth\App\Services\AuthService::makeLogin($user, 'google'));
        $this->assertFalse(\WP_Session_Tokens::get_instance($user->ID)->verify($old));
        $this->assertCount(1, \WP_Session_Tokens::get_instance($user->ID)->get_all());
    }

    public function testSessionLimitPreservesTheRecoveryOperatorsReplacementLogin()
    {
        $user = $this->factory->user->create_and_get(['role' => 'administrator']);
        wp_set_current_user($user->ID);
        $this->saveSettings(['session_limit' => 1]);
        $old = $this->issueLimitedCookie($user->ID);
        \FluentAuth\App\Services\Recovery\RecoveryService::secureNow(false);
        $this->assertFalse(\WP_Session_Tokens::get_instance($user->ID)->verify($old));
        $this->assertCount(1, \WP_Session_Tokens::get_instance($user->ID)->get_all());
    }

    public function testSessionLimitStopsOnlyTheLoginAfterRepeatedStorageConflicts()
    {
        global $wpdb;
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1]);
        $race = function ($sql) use (&$race, $manager, $wpdb) {
            if (strpos($sql, "UPDATE {$wpdb->usermeta} SET meta_value") === 0 && strpos($sql, 'BINARY meta_value') !== false) {
                remove_filter('query', $race);
                $manager->create(time() + DAY_IN_SECONDS);
                add_filter('query', $race);
            }
            return $sql;
        };
        add_filter('query', $race);
        try {
            $this->issueLimitedCookie($id);
            $this->fail('A changing store must not produce an unbounded authenticated login');
        } catch (\WPDieException $e) {
            $this->assertStringContainsString('Please try again', $e->getMessage());
            $this->assertTrue($manager->verify($old), 'Failed admission must not evict existing sessions');
        } finally { remove_filter('query', $race); }
    }

    public function testSessionLimitSurvivesAnOlderClientsSaveAndSupportedFlagIsNotStored()
    {
        $this->saveSettings(['session_limit' => 2]);
        $settings = Helper::getAuthSettings(); unset($settings['session_limit']);
        $request = new \WP_REST_Request();
        $request->set_param('settings', $settings + ['session_limit_supported' => false]);
        $saved = SettingsController::updateSettings($request);
        $this->assertNotWPError($saved);
        $this->assertSame(2, $saved['settings']['session_limit'] ?? null);
        $this->assertArrayNotHasKey('session_limit_supported', get_option('__fls_auth_settings'));
    }

    public function testExistingSitesGetRememberMeCheckedByDefault()
    {
        update_option('__fls_auth_settings', ['login_try_limit' => 5]);
        Helper::resetStatics();

        $this->assertTrue(SessionLengthHandler::rememberByDefault());
    }

    public function testWpLoginFormFollowsTheSetting()
    {
        $this->assertStringContainsString('checked="checked"', wp_login_form(['echo' => false]));

        $this->saveSettings(['remember_default' => 'no']);
        $this->assertStringNotContainsString('checked="checked"', wp_login_form(['echo' => false]));
    }

    public function testWpLoginScreenChecksTheBoxOnlyOnFirstVisit()
    {
        $handler = new SessionLengthHandler();

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->assertStringContainsString('rememberme', $this->footer($handler));

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->assertSame('', $this->footer($handler));

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->saveSettings(['remember_default' => 'no']);
        $this->assertSame('', $this->footer($handler));
    }

    private function footer(SessionLengthHandler $handler)
    {
        ob_start();
        $handler->checkRememberMeOnWpLogin();
        return ob_get_clean();
    }
}

class SessionLimitCustomStore extends \WP_User_Meta_Session_Tokens {}
