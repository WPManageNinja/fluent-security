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
        $arm = $this->armPruningRace($race);
        try {
            $incoming = $this->issueLimitedCookie($id);
            $this->assertTrue($interleaved, 'Revocation ran between the actual database read and conditional write');
            $this->assertFalse($manager->verify($old));
            $this->assertTrue($manager->verify($incoming));
            $this->assertCount(1, $manager->get_all());
        } finally {
            remove_filter('query', $race);
            remove_action('set_logged_in_cookie', $arm, PHP_INT_MAX);
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
        $arm = $this->armPruningRace($race);
        try {
            $loser = $this->issueLimitedCookie($id);
            $this->assertNotSame('', $winner, 'A second completed login interleaved at the actual conditional write');
            $this->assertFalse($manager->verify($loser));
            $this->assertTrue($manager->verify($winner));
            $this->assertCount(1, $manager->get_all());
        } finally { remove_filter('query', $race); remove_action('set_logged_in_cookie', $arm, PHP_INT_MAX); }
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

    /** @dataProvider nativeLogoutCounts */
    public function testSessionLimitSurvivesANativeLogoutFinishingAfterPruning($count)
    {
        $id = $this->factory->user->create();
        $manager = \WP_Session_Tokens::get_instance($id);
        $old = [];
        for ($i = 0; $i < $count; $i++) { $old[] = $manager->create(time() + DAY_IN_SECONDS); }
        $this->saveSettings(['session_limit' => 1]);
        $incoming = '';
        $hook = $count === 1 ? 'delete_user_metadata' : 'update_user_metadata';
        $race = function ($check, $uid, $key) use (&$race, &$incoming, $id, $hook) {
            if ($uid === $id && $key === 'session_tokens') {
                remove_filter($hook, $race);
                $incoming = $this->issueLimitedCookie($id);
            }
            return $check;
        };
        add_filter($hook, $race, 10, 3);
        try {
            $manager->destroy($old[$count - 1]);
            $this->assertNotSame('', $incoming, 'A new sign-in completed before the old native logout write');
            $this->assertTrue($manager->verify($incoming), 'Finishing the earlier logout must preserve the incoming login');
            $this->assertFalse($manager->verify($old[0]), 'An evicted session must stay revoked');
            $this->assertCount(1, $manager->get_all());
        } finally { remove_filter($hook, $race); }
    }

    public function nativeLogoutCounts() { return [[1], [3]]; }

    public function testNativeCoordinationIsSelectedWithEvictionDisabled()
    {
        $this->assertSame(\FluentAuth\App\Services\NativeSessionTokens::class, get_class(\WP_Session_Tokens::get_instance(1)));
    }

    public function testCustomDatabaseKeepsTheOriginalNativeManager()
    {
        global $wpdb; $original = $wpdb;
        try { $wpdb = new class extends \wpdb { public function __construct() {} };
            $this->assertSame('WP_User_Meta_Session_Tokens', get_class(\WP_Session_Tokens::get_instance(1)));
        } finally { $wpdb = $original; }
    }

    public function testNativeUpdateDoesNotRestoreATokenRevokedDuringItsWrite()
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $token = $manager->create(time() + DAY_IN_SECONDS);
        $session = $manager->get($token); $session['extra'] = 'updated';
        $race = function ($check, $uid, $key) use (&$race, $manager, $token, $id) {
            if ($uid === $id && $key === 'session_tokens') {
                remove_filter('update_user_metadata', $race); $manager->destroy($token);
            }
            return $check;
        };
        add_filter('update_user_metadata', $race, 10, 3);
        try { $manager->update($token, $session); $this->assertFalse($manager->verify($token)); }
        finally { remove_filter('update_user_metadata', $race); }
    }

    public function testNativeDestroyOthersDoesNotRestoreARevokedKeepToken()
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $keep = $manager->create(time() + DAY_IN_SECONDS); $manager->create(time() + DAY_IN_SECONDS);
        $race = function ($check, $uid, $key) use (&$race, $manager, $keep, $id) {
            if ($uid === $id && $key === 'session_tokens') {
                remove_filter('update_user_metadata', $race); $manager->destroy($keep);
            }
            return $check;
        };
        add_filter('update_user_metadata', $race, 10, 3);
        try { $manager->destroy_others($keep); $this->assertFalse($manager->verify($keep)); $this->assertCount(0, $manager->get_all()); }
        finally { remove_filter('update_user_metadata', $race); }
    }

    public function testNativeDuplicateRowsAreRemovedOnTheNextWriteAndAllAreRemovedOnLogout()
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        add_user_meta($id, 'session_tokens', null);
        $manager->create(time() + DAY_IN_SECONDS);
        add_user_meta($id, 'session_tokens', ['ignored' => ['expiration' => time() + DAY_IN_SECONDS]]);
        $this->saveSettings(['session_limit' => 1]); $incoming = $this->issueLimitedCookie($id);
        $this->assertCount(1, get_user_meta($id, 'session_tokens')); $this->assertTrue($manager->verify($incoming));
        add_user_meta($id, 'session_tokens', ['ignored' => ['expiration' => time() + DAY_IN_SECONDS]]);
        $manager->destroy_all(); $this->assertFalse(metadata_exists('user', $id, 'session_tokens'));
    }

    public function unchangedWritesWithDivergedDuplicates()
    {
        return [
            'absent logout' => [function ($manager, $token) { $manager->destroy('absent-token'); }],
            'others with one session' => [function ($manager, $token) { $manager->destroy_others($token); }],
            'unchanged update' => [function ($manager, $token) { $manager->update($token, $manager->get($token)); }],
        ];
    }

    /** @dataProvider unchangedWritesWithDivergedDuplicates */
    public function testNativeUnchangedWriteWithDivergedDuplicatesSucceedsAndRepairsThem($write)
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $token = $manager->create(time() + DAY_IN_SECONDS);
        add_user_meta($id, 'session_tokens', ['stale' => ['expiration' => time() + DAY_IN_SECONDS]]);
        $duplicate = (int)max(array_map('intval', $GLOBALS['wpdb']->get_col($GLOBALS['wpdb']->prepare(
            "SELECT umeta_id FROM {$GLOBALS['wpdb']->usermeta} WHERE user_id = %d AND meta_key = %s", $id, 'session_tokens'
        ))));
        wp_cache_get($id, 'user_meta') ?: update_meta_cache('user', [$id]);
        $deleted = [];
        $listen = function ($ids, $uid, $key) use (&$deleted, $id) {
            if ((int)$uid === $id && $key === 'session_tokens') { $deleted = array_merge($deleted, array_map('intval', (array)$ids)); }
        };
        add_action('deleted_user_meta', $listen, 10, 3);
        try { $write($manager, $token); } finally { remove_action('deleted_user_meta', $listen, 10); }
        $this->assertSame([$duplicate], $deleted, 'The removed duplicate is reported to metadata listeners');
        $this->assertFalse(wp_cache_get($id, 'user_meta'), 'The user meta cache is invalidated');
        $this->assertCount(1, get_user_meta($id, 'session_tokens'));
        $this->assertTrue($manager->verify($token));
    }

    public function testNativeRevocationOverlappingTheDuplicateRepairLeavesNoRevokedCopy()
    {
        global $wpdb;
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $revoked = $manager->create(time() + DAY_IN_SECONDS);
        add_user_meta($id, 'session_tokens', get_user_meta($id, 'session_tokens', true));
        $fired = false;
        $race = function ($sql) use (&$race, &$fired, $manager, $revoked, $wpdb) {
            if (preg_match("/^(UPDATE|DELETE FROM) {$wpdb->usermeta} .*umeta_id (<>|IN)/s", $sql)) {
                remove_filter('query', $race); $fired = true; $manager->destroy($revoked);
            }
            return $sql;
        };
        add_filter('query', $race);
        try { $fresh = $manager->create(time() + DAY_IN_SECONDS); } finally { remove_filter('query', $race); }
        $this->assertTrue($fired, 'The revocation ran at the duplicate repair of the overlapped operation');
        $rows = get_user_meta($id, 'session_tokens');
        $this->assertCount(1, $rows, 'No duplicate copy survives');
        $this->assertArrayNotHasKey(hash('sha256', $revoked), $rows[0]);
        $this->assertTrue($manager->verify($fresh)); $this->assertFalse($manager->verify($revoked));
    }

    public function testNativeMetadataHooksCacheAndVetoRemainEffective()
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $events = []; $listeners = [];
        foreach (['add', 'added', 'update', 'updated', 'delete', 'deleted'] as $event) {
            $listener = function (...$args) use (&$events, $id, $event) {
                $offset = $event === 'add' ? 0 : 1;
                if ((int)$args[$offset] === $id && $args[$offset + 1] === 'session_tokens') { $events[] = $event; }
            };
            add_action($event . '_user_meta', $listener, 10, 4); $listeners[$event] = $listener;
        }
        try {
            $first = $manager->create(time() + DAY_IN_SECONDS); $manager->get_all();
            $second = $manager->create(time() + DAY_IN_SECONDS);
            $this->assertCount(2, $manager->get_all(), 'Committed writes invalidate the warmed metadata cache');
            $veto = function ($check, $uid, $key) use ($id) { return $uid === $id && $key === 'session_tokens' ? false : $check; };
            add_filter('update_user_metadata', $veto, 10, 3);
            try { $blocked = $manager->create(time() + DAY_IN_SECONDS); $this->assertFalse($manager->verify($blocked)); }
            finally { remove_filter('update_user_metadata', $veto); }
            $session = $manager->get($first); $session['extra'] = 'keep\\value'; $manager->update($first, $session);
            $this->assertSame('keep\\value', $manager->get($first)['extra']);
            $manager->destroy($first); $manager->destroy($second);
            $this->assertSame(['add', 'added', 'update', 'updated', 'update', 'updated', 'update', 'updated', 'delete', 'deleted'], $events);
            $this->assertFalse(metadata_exists('user', $id, 'session_tokens'));
            $denyAdd = function ($check, $uid, $key) use ($id) { return $uid === $id && $key === 'session_tokens' ? false : $check; };
            add_filter('add_user_metadata', $denyAdd, 10, 3);
            try { $this->assertFalse($manager->verify($manager->create(time() + DAY_IN_SECONDS))); }
            finally { remove_filter('add_user_metadata', $denyAdd); }
        } finally { foreach ($listeners as $event => $listener) { remove_action($event . '_user_meta', $listener); } }
    }

    public function testNativeReadOverrideStillDisablesTheCap()
    {
        $id = $this->factory->user->create(); $virtual = [];
        $override = function ($value, $uid, $key) use ($id, &$virtual) { return $uid === $id && $key === 'session_tokens' ? [$virtual] : $value; };
        $save = function ($value, $uid, $key, $next) use ($id, &$virtual) {
            if ($uid === $id && $key === 'session_tokens') { $virtual = $next; return true; } return $value;
        };
        $erase = function ($value, $uid, $key) use ($id, &$virtual) {
            if ($uid === $id && $key === 'session_tokens') { $virtual = []; return true; } return $value;
        };
        add_filter('get_user_metadata', $override, 10, 3);
        add_filter('update_user_metadata', $save, 10, 4); add_filter('delete_user_metadata', $erase, 10, 3);
        try {
            $this->assertFalse(SessionLengthHandler::supportsLimit($id));
            $manager = \WP_Session_Tokens::get_instance($id); $first = $manager->create(time() + DAY_IN_SECONDS);
            $second = $manager->create(time() + DAY_IN_SECONDS); $this->assertCount(2, $manager->get_all());
            $manager->destroy($first); $this->assertTrue($manager->verify($second));
            $manager->destroy($second); $this->assertSame([], $virtual);
        } finally { remove_filter('get_user_metadata', $override); remove_filter('update_user_metadata', $save); remove_filter('delete_user_metadata', $erase); }
    }

    public function testFirstNativeInsertDoesNotWaitForAnotherConnectionsLock()
    {
        global $wpdb;
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $other = new \wpdb(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST); $name = ''; $held = false;
        $race = function ($sql) use (&$race, &$name, &$held, $other) {
            if (preg_match("/SELECT GET_LOCK\\('([^']+)', 0\\)/", $sql, $match)) {
                remove_filter('query', $race); $name = $match[1]; $held = (string)$other->get_var($sql) === '1';
            }
            return $sql;
        };
        add_filter('query', $race);
        try {
            try { $manager->create(time() + DAY_IN_SECONDS); $this->fail('Contending creation must report a retry'); }
            catch (\WPDieException $e) { $this->assertStringContainsString('Please try again', $e->getMessage()); }
            $this->assertTrue($held, 'A separate database connection acquired the initial-insertion lock');
            $this->assertFalse(metadata_exists('user', $id, 'session_tokens'), 'A contending initial insert does not create another metadata row');
        } finally { remove_filter('query', $race); if ($held) { $other->get_var($other->prepare('SELECT RELEASE_LOCK(%s)', $name)); } $other->close(); }
        $this->assertTrue($manager->verify($manager->create(time() + DAY_IN_SECONDS)), 'A later attempt works after lock release');
    }

    public function testConcurrentNativeCreatesKeepBothSessions()
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS); $other = '';
        $race = function ($check, $uid, $key) use (&$race, &$other, $manager, $id) {
            if ($uid === $id && $key === 'session_tokens') { remove_filter('update_user_metadata', $race); $other = $manager->create(time() + DAY_IN_SECONDS); }
            return $check;
        };
        add_filter('update_user_metadata', $race, 10, 3);
        try {
            $first = $manager->create(time() + DAY_IN_SECONDS);
            $this->assertTrue($manager->verify($old)); $this->assertTrue($manager->verify($first)); $this->assertTrue($manager->verify($other));
            $this->assertCount(3, $manager->get_all());
        } finally { remove_filter('update_user_metadata', $race); }
    }

    public function testSessionMarkerDoesNotChangeRecoveryCountsOrSmartcodeSecrecy()
    {
        $user = $this->factory->user->create_and_get(); $this->saveSettings(['session_limit' => 1]);
        $count = new \ReflectionMethod(\FluentAuth\App\Services\Recovery\RecoveryService::class, 'countSessions'); $count->setAccessible(true);
        $before = $count->invoke(null); $this->issueLimitedCookie($user->ID);
        $this->assertSame($before + 1, $count->invoke(null));
        $this->assertSame('', (new \FluentAuth\App\Services\SmartCodeParser())->parse('{{user.meta.session_tokens}}', $user));
    }

    public function testNativeRevocationReportsPersistentWriteContention()
    {
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $token = $manager->create(time() + DAY_IN_SECONDS); $manager->create(time() + DAY_IN_SECONDS);
        $race = function ($check, $uid, $key) use (&$race, $manager, $id) {
            if ($uid === $id && $key === 'session_tokens') {
                remove_filter('update_user_metadata', $race); $manager->create(time() + DAY_IN_SECONDS); add_filter('update_user_metadata', $race, 10, 3);
            }
            return $check;
        };
        add_filter('update_user_metadata', $race, 10, 3);
        try {
            try { $manager->destroy($token); $this->fail('A failed revocation must not be reported as complete'); }
            catch (\WPDieException $e) { $this->assertStringContainsString('Please try again', $e->getMessage()); }
        } finally { remove_filter('update_user_metadata', $race); }
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
        $arm = $this->armPruningRace($race);
        try {
            $this->issueLimitedCookie($id);
            $this->fail('A changing store must not produce an unbounded authenticated login');
        } catch (\WPDieException $e) {
            $this->assertStringContainsString('Please try again', $e->getMessage());
            $this->assertTrue($manager->verify($old), 'Failed admission must not evict existing sessions');
        } finally { remove_filter('query', $race); remove_action('set_logged_in_cookie', $arm, PHP_INT_MAX); }
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

    // Another connection holds the stored row's lock and commits a revocation while the plugin's write waits on it.
    public function testNativeWriteWaitingOnTheRowLockDoesNotRestoreARevocationCommittedMeanwhile()
    {
        global $wpdb;
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $revoked = $manager->create(time() + DAY_IN_SECONDS); $kept = $manager->create(time() + DAY_IN_SECONDS);
        $row = $wpdb->get_row($wpdb->prepare("SELECT umeta_id, meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s ORDER BY umeta_id LIMIT 1", $id, 'session_tokens'));
        $map = maybe_unserialize($row->meta_value); unset($map[hash('sha256', $revoked)]);
        self::commit_transaction();
        $isolation = str_replace('-', ' ', (string)$wpdb->get_var('SELECT @@SESSION.transaction_isolation'));
        $wpdb->query('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED'); self::commit_transaction();
        $holder = null; $pipes = [];
        try {
            $env = ['PATH' => (string)getenv('PATH'), 'FLS_H' => DB_HOST, 'FLS_U' => DB_USER, 'FLS_P' => DB_PASSWORD, 'FLS_D' => DB_NAME,
                'FLS_T' => $wpdb->usermeta, 'FLS_I' => (string)$row->umeta_id, 'FLS_V' => base64_encode(maybe_serialize($map))];
            $script = '$h = getenv("FLS_H"); $port = 3306; if (strpos($h, ":") !== false) { list($h, $port) = explode(":", $h, 2); }'
                . '$m = new mysqli($h, getenv("FLS_U"), getenv("FLS_P"), getenv("FLS_D"), (int)$port); $m->query("START TRANSACTION");'
                . '$v = base64_decode(getenv("FLS_V")); $i = (int)getenv("FLS_I");'
                . '$s = $m->prepare("UPDATE `" . getenv("FLS_T") . "` SET meta_value = ? WHERE umeta_id = ?"); $s->bind_param("si", $v, $i); $s->execute();'
                . 'echo "locked\n"; fflush(STDOUT); usleep(700000); $m->query("COMMIT"); echo "committed\n";';
            $holder = proc_open([PHP_BINARY, '-r', $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
            $this->assertSame("locked\n", fgets($pipes[1]), 'The other connection holds the stored row lock');
            $started = microtime(true);
            $fresh = $manager->create(time() + DAY_IN_SECONDS);
            $this->assertGreaterThan(0.3, microtime(true) - $started, 'The plugin write waited on the other connection\'s row lock');
            $this->assertSame("committed\n", fgets($pipes[1]));
            $this->assertFalse($manager->verify($revoked), 'A revocation committed during the wait stays revoked');
            $this->assertTrue($manager->verify($kept));
            $this->assertTrue($manager->verify($fresh));
        } finally {
            if ($holder) { fclose($pipes[1]); fclose($pipes[2]); proc_close($holder); }
            $wpdb->query("SET SESSION TRANSACTION ISOLATION LEVEL {$isolation}");
            $wpdb->delete($wpdb->usermeta, ['user_id' => $id]); $wpdb->delete($wpdb->users, ['ID' => $id]);
            self::commit_transaction(); clean_user_cache($id);
        }
    }

    public function failedReadRevocations()
    {
        return [
            'all' => [function ($manager, $token, $other) { $manager->destroy_all(); }],
            'one' => [function ($manager, $token, $other) { $manager->destroy($token); }],
            'others' => [function ($manager, $token, $other) { $manager->destroy_others($other); }],
        ];
    }

    /** @dataProvider failedReadRevocations */
    public function testNativeRevocationReportsAFailedSessionRead($revoke)
    {
        global $wpdb;
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $token = $manager->create(time() + DAY_IN_SECONDS); $other = $manager->create(time() + DAY_IN_SECONDS);
        $break = function ($sql) use (&$break, $wpdb) {
            if (strpos($sql, "SELECT umeta_id, meta_value FROM {$wpdb->usermeta} ") === 0) {
                remove_filter('query', $break);
                return str_replace("FROM {$wpdb->usermeta} ", "FROM {$wpdb->usermeta}_missing ", $sql);
            }
            return $sql;
        };
        $suppressed = $wpdb->suppress_errors(true);
        add_filter('query', $break);
        try {
            try { $revoke($manager, $token, $other); $this->fail('A revocation whose session read failed must not report success'); }
            catch (\WPDieException $e) { $this->assertStringContainsString('Please try again', $e->getMessage()); }
        } finally { remove_filter('query', $break); $wpdb->suppress_errors($suppressed); }
        $this->assertTrue($manager->verify($token), 'The stored session was not touched');
    }

    public function testSessionLimitStopsTheLoginWhenThePruningCheckCannotRead()
    {
        global $wpdb;
        $id = $this->factory->user->create(); $manager = \WP_Session_Tokens::get_instance($id);
        $old = $manager->create(time() + DAY_IN_SECONDS);
        $this->saveSettings(['session_limit' => 1]);
        $reads = 0;
        $race = function ($sql) use (&$race, &$reads, $wpdb) {
            if (strpos($sql, "SELECT umeta_id, meta_value FROM {$wpdb->usermeta} ") === 0 && ++$reads === 2) {
                remove_filter('query', $race);
                return str_replace("FROM {$wpdb->usermeta} ", "FROM {$wpdb->usermeta}_missing ", $sql);
            }
            return $sql;
        };
        $suppressed = $wpdb->suppress_errors(true);
        $arm = $this->armPruningRace($race);
        try {
            $this->issueLimitedCookie($id);
            $this->fail('A login whose limit could not be checked must not finish silently');
        } catch (\WPDieException $e) {
            $this->assertStringContainsString('Please try again', $e->getMessage());
            $this->assertSame(2, $reads);
        } finally { remove_filter('query', $race); remove_action('set_logged_in_cookie', $arm, PHP_INT_MAX); $wpdb->suppress_errors($suppressed); }
    }

    private function armPruningRace($race)
    {
        $armed = false;
        $arm = function () use ($race, &$armed) {
            if (!$armed) {
                $armed = true;
                add_filter('query', $race);
            }
        };
        add_action('set_logged_in_cookie', $arm, PHP_INT_MAX, 0);
        return $arm;
    }

    private function footer(SessionLengthHandler $handler)
    {
        ob_start();
        $handler->checkRememberMeOnWpLogin();
        return ob_get_clean();
    }
}

class SessionLimitCustomStore extends \WP_User_Meta_Session_Tokens {}
