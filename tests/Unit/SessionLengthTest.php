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

    public function setUp(): void
    {
        parent::setUp();
        $this->method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : null;
        delete_option('__fls_auth_settings');
        Helper::resetStatics();
    }

    public function tearDown(): void
    {
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
