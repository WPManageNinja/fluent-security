<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;

class AlternativeEmailMethod extends EmailTwoFaMethod
{
    public function getKey()
    {
        return 'test_email_alt';
    }
}

class TwoFaChallengeLifecycleTest extends BaseTestCase
{
    private $handler;
    private $user;

    public function setUp(): void
    {
        parent::setUp();
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_login_hashes");
        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
        $this->handler = new TwoFaHandler();
        $this->user = $this->factory->user->create_and_get(['role' => 'administrator']);
    }

    public function tearDown(): void
    {
        unset($_REQUEST['login_hash'], $_REQUEST['login_passcode']);
        remove_all_filters('fluent_auth/2fa_methods');
        TwoFaService::resetMethods();
        parent::tearDown();
    }

    private function issue()
    {
        $code = null;
        $capture = function ($data) use (&$code) { $code = $data['two_fa_code']; };
        add_action('fls_send_2fa_code', $capture);
        $result = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both', admin_url('profile.php'));
        remove_action('fls_send_2fa_code', $capture);
        return [$result['login_hash'], $code];
    }

    private function row($hash)
    {
        return flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->first();
    }

    public function throwingDieHandler()
    {
        return function ($message = '') { throw new \WPDieException((string)$message); };
    }

    private function verify($hash, $code)
    {
        $_REQUEST['login_hash'] = $hash;
        $_REQUEST['login_passcode'] = $code;
        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);
        ob_start();
        try {
            $this->handler->verifyChallenge();
        } catch (\WPDieException $e) {
            // wp_send_json terminates the request.
        } finally {
            $output = ob_get_clean();
            remove_filter('wp_doing_ajax', '__return_true');
            remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);
        }
        return json_decode($output, true);
    }

    private function switchMethod($hash)
    {
        $_REQUEST['login_hash'] = $hash;
        $location = null;
        $capture = function ($url) use (&$location) {
            $location = $url;
            throw new \RuntimeException('redirect');
        };
        add_filter('wp_redirect', $capture);
        try {
            $this->handler->switchMethod();
        } catch (\RuntimeException $e) {
            $this->assertSame('redirect', $e->getMessage());
        } finally {
            remove_filter('wp_redirect', $capture);
        }
        return $location;
    }

    private function enableAlternative()
    {
        add_filter('fluent_auth/2fa_methods', function ($methods) {
            $methods[] = new AlternativeEmailMethod();
            return $methods;
        });
        TwoFaService::resetMethods();
    }

    public function testChallengeIsSpentBeforeAuthenticationAndCannotBeClaimedTwice()
    {
        [$hash, $code] = $this->issue();
        $observed = null;
        $secondClaim = null;
        $stale = $this->row($hash);
        $spy = function ($user) use ($hash, $stale, &$observed, &$secondClaim) {
            $observed = $this->row($hash)->status;
            // Simulate a second request which already read and verified the same proof.
            if (method_exists($this->handler, 'claimPendingChallenge')) {
                $claim = new \ReflectionMethod($this->handler, 'claimPendingChallenge');
                $claim->setAccessible(true);
                $secondClaim = $claim->invoke($this->handler, $stale, 'used');
            }
            return $user;
        };
        add_filter('authenticate', $spy, 9999);
        try {
            $response = $this->verify($hash, $code);
        } finally {
            remove_filter('authenticate', $spy, 9999);
        }
        $this->assertArrayHasKey('redirect', $response);
        $this->assertSame('used', $observed, 'Consume proof before reaching authentication hooks');
        $this->assertFalse($secondClaim);
    }

    public function testAConcurrentRedemptionBeforeProofReturnsPreventsAnotherLogin()
    {
        [$hash, $code] = $this->issue();
        $consume = function ($valid) use ($hash) {
            flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->update(['status' => 'used']);
            return $valid;
        };
        $logins = 0;
        $spy = function () use (&$logins) { $logins++; };
        add_filter('check_password', $consume);
        add_action('wp_login', $spy);
        try {
            $response = $this->verify($hash, $code);
        } finally {
            remove_filter('check_password', $consume);
            remove_action('wp_login', $spy);
        }
        $this->assertArrayNotHasKey('redirect', $response);
        $this->assertSame(0, $logins);
        $this->assertFalse(Helper::isTokenVerifiedLogin());
    }

    /** @dataProvider ineligibleSwitches */
    public function testIneligibleChallengeCannotBeSwitched($field, $value)
    {
        $this->enableAlternative();
        [$hash] = $this->issue();
        if ($value === 'expired') {
            $value = date('Y-m-d H:i:s', current_time('timestamp') - 660);
        }
        flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->update([$field => $value]);
        $this->assertSame(wp_login_url(), $this->switchMethod($hash));
        $this->assertSame(1, (int)flsDb()->table('fls_login_hashes')->count());
    }

    public function ineligibleSwitches()
    {
        return [
            ['created_at', 'expired'], ['valid_till', 'expired'],
            ['used_count', TwoFaHandler::MAX_VERIFY_ATTEMPTS], ['status', 'used'], ['status', 'failed']
        ];
    }

    public function testValidProofSurvivesAConcurrentWrongGuessBelowTheCap()
    {
        [$hash, $code] = $this->issue();
        $wrongGuess = function ($valid) use ($hash) {
            flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->update(['used_count' => 1]);
            return $valid;
        };
        add_filter('check_password', $wrongGuess);
        try {
            $response = $this->verify($hash, $code);
        } finally {
            remove_filter('check_password', $wrongGuess);
        }
        $this->assertArrayHasKey('redirect', $response);
        $this->assertSame('used', $this->row($hash)->status);
        $this->assertSame(1, (int)$this->row($hash)->used_count);
    }

    public function testRecoveryCodeStillLogsInAfterAConcurrentWrongGuess()
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
        TotpTwoFaMethod::activate($this->user, TotpProvider::generateSecret());
        $codes = TotpTwoFaMethod::generateRecoveryCodes($this->user);
        $issued = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both', null, new TotpTwoFaMethod());
        $hash = $issued['login_hash'];
        $wrongGuess = function () use ($hash) {
            flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->update(['used_count' => 1]);
        };
        add_action('fluent_auth/recovery_code_used', $wrongGuess);
        try {
            $response = $this->verify($hash, $codes[0]);
        } finally {
            remove_action('fluent_auth/recovery_code_used', $wrongGuess);
        }
        $this->assertArrayHasKey('redirect', $response);
        $this->assertSame('used', $this->row($hash)->status);
        $this->assertSame(TotpTwoFaMethod::RECOVERY_CODE_COUNT - 1, TotpTwoFaMethod::getRemainingRecoveryCount($this->user));
    }

    public function testValidSwitchPreservesLifetimeAttemptsAndDestination()
    {
        $this->enableAlternative();
        [$hash] = $this->issue();
        flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->update([
            'created_at' => date('Y-m-d H:i:s', current_time('timestamp') - 300),
            'valid_till' => date('Y-m-d H:i:s', current_time('timestamp') + 300),
            'used_count' => 2
        ]);
        $old = $this->row($hash);
        $this->switchMethod($hash);
        $replacement = flsDb()->table('fls_login_hashes')->where('status', 'issued')->first();
        $this->assertNotNull($replacement);
        $this->assertNotSame($hash, $replacement->login_hash);
        $this->assertSame('failed', $this->row($hash)->status);
        $this->assertSame('test_email_alt', $replacement->use_type);
        $this->assertSame($old->created_at, $replacement->created_at);
        $this->assertSame($old->valid_till, $replacement->valid_till);
        $this->assertSame(2, (int)$replacement->used_count);
        $this->assertSame($old->redirect_intend, $replacement->redirect_intend);
    }

    public function testNoAlternativeKeepsTheOriginalChallenge()
    {
        [$hash] = $this->issue();
        $this->assertSame(TwoFaService::getChallengeUrl($hash), $this->switchMethod($hash));
        $this->assertSame('issued', $this->row($hash)->status);
    }

    public function testLateWrongProofCannotOverwriteConsumedState()
    {
        [$hash] = $this->issue();
        $stale = $this->row($hash);
        flsDb()->table('fls_login_hashes')->where('login_hash', $hash)->update(['status' => 'used']);
        $method = new \ReflectionMethod($this->handler, 'recordFailedAttempt');
        $method->setAccessible(true);
        $method->invoke($this->handler, $stale, $this->user, new EmailTwoFaMethod());
        $this->assertSame('used', $this->row($hash)->status);
        $this->assertSame(0, (int)$this->row($hash)->used_count);
    }
}
