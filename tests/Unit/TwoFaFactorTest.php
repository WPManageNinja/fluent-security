<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\AuthFactor;
use FluentAuth\App\Services\TwoFa\BaseTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;

/**
 * A stand in for an authenticator app or a passkey: it proves a device, which no
 * mailbox or identity provider ever does.
 */
class FakeDeviceMethod extends BaseTwoFaMethod
{
    public function getKey()
    {
        return 'fake_device';
    }

    public function getTitle()
    {
        return 'Fake Device';
    }

    public function getSatisfiedFactor()
    {
        return AuthFactor::DEVICE;
    }

    public function isAvailableForUser($user)
    {
        return true;
    }

    public function renderForm($data)
    {
        return '<form id="fls_fake_device"></form>';
    }

    public function verifyProof($user, $logHash, $request)
    {
        return Arr::get($request, 'login_passcode') === 'GOODCODE';
    }
}

/**
 * Two factor authentication is only worth the friction when the second step proves
 * something the first one did not. These tests pin that rule down in both directions:
 * a method proving what has already been proven is skipped, and a method proving
 * anything else survives every entry point - which is what stops magic login or a
 * social provider from quietly becoming a way around an authenticator app.
 */
class TwoFaFactorTest extends BaseTestCase
{
    private $handler;

    private $user;

    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_auth_logs");
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
        remove_all_filters('fluent_auth/2fa_methods');
        TwoFaService::resetMethods();
        parent::tearDown();
    }

    private function registerDeviceMethod()
    {
        add_filter('fluent_auth/2fa_methods', function ($methods) {
            $methods[] = new FakeDeviceMethod();
            return $methods;
        });

        TwoFaService::resetMethods();
    }

    public function testAPasswordLoginIsStillAskedForTheEmailedCode()
    {
        // Nothing declared, so the login is treated as a password - the default.
        $this->assertNotFalse($this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both'));
    }

    public function testAMagicLinkIsNotAskedForAnEmailedCode()
    {
        Helper::setSatisfiedFactors([AuthFactor::EMAIL]);

        $this->assertFalse(
            $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both'),
            'Redeeming a magic link already proved the mailbox; asking it for a code is one factor twice.'
        );
    }

    public function testSocialLoginIsNotAskedForAnEmailedCode()
    {
        // The account is matched on an address the provider has already verified.
        Helper::setSatisfiedFactors([AuthFactor::IDP, AuthFactor::EMAIL]);

        $this->assertFalse($this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both'));
    }

    public function testADeviceFactorSurvivesAMagicLink()
    {
        $this->registerDeviceMethod();

        Helper::setSatisfiedFactors([AuthFactor::EMAIL]);

        $return = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return, 'A passkey or authenticator app must not be skipped for magic login.');

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('fake_device', $row->use_type);
    }

    public function testADeviceFactorSurvivesSocialLogin()
    {
        $this->registerDeviceMethod();

        Helper::setSatisfiedFactors([AuthFactor::IDP, AuthFactor::EMAIL]);

        $return = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('fake_device', $row->use_type);
    }

    public function testTheEmailedCodeIsPreferredWhenBothApplyToAPasswordLogin()
    {
        $this->registerDeviceMethod();

        $return = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        // Registration order decides, and email is registered first.
        $this->assertSame('email_2_fa', $row->use_type);
    }

    public function testAChallengeIsNotRaisedForAFactorAlreadyProven()
    {
        add_filter('fluent_auth/2fa_challenge_required', '__return_true');

        // Email 2FA off, so only the under-attack challenge could raise anything.
        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        Helper::setSatisfiedFactors([AuthFactor::EMAIL]);

        $handler = new TwoFaHandler();

        $this->assertFalse(
            $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both'),
            'The challenge exists to ask for the mailbox, which a magic link has already shown.'
        );

        remove_filter('fluent_auth/2fa_challenge_required', '__return_true');
    }

    public function testAChallengeStillFallsBackToEmailForAPasswordLogin()
    {
        add_filter('fluent_auth/2fa_challenge_required', '__return_true');

        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $handler = new TwoFaHandler();

        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame(TwoFaHandler::CHALLENGE_USE_TYPE, $row->use_type);

        remove_filter('fluent_auth/2fa_challenge_required', '__return_true');
    }

    public function testANonEmailMethodVerifiesThroughTheSameFlow()
    {
        $this->registerDeviceMethod();

        Helper::setSatisfiedFactors([AuthFactor::EMAIL]);

        $return = $this->handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertSame(false, $this->verify('WRONGCODE', $return['login_hash'])['redirect'] ?? false);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame(1, (int)$row->used_count);

        $result = $this->verify('GOODCODE', $return['login_hash']);

        $this->assertArrayHasKey('redirect', $result);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('used', $row->status);
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    /**
     * verifyChallenge() terminates through wp_send_json(); capture what it emitted.
     */
    private function verify($code, $hash)
    {
        $_REQUEST['login_passcode'] = $code;
        $_REQUEST['login_hash'] = $hash;

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        ob_start();
        try {
            $this->handler->verifyChallenge();
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        unset($_REQUEST['login_passcode'], $_REQUEST['login_hash']);

        return json_decode($output, true);
    }
}
