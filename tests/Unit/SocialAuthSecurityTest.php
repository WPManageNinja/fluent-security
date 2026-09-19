<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\GoogleAuthService;

/**
 * Social login hands us an email address and we sign in whichever WordPress account
 * holds it, so the guarantees around that address are the whole security boundary.
 */
class SocialAuthSecurityTest extends BaseTestCase
{
    private $cookieBackup;

    public function setUp(): void
    {
        parent::setUp();

        $this->cookieBackup = $_COOKIE;
        unset($_COOKIE['fs_auth_state']);

        update_option('__fls_social_auth_settings', [
            // Anything but 'wp_config', or the keys get read from constants instead.
            'google_key_method'    => 'db',
            'google_client_id'     => '1234567890-test.apps.googleusercontent.com',
            'google_client_secret' => 'secret',
            'enable_google'        => 'yes',
        ]);
        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        $_COOKIE = $this->cookieBackup;
        unset($_POST['credential'], $_POST['mode']);
        parent::tearDown();
    }

    /**
     * Stands in for oauth2.googleapis.com/tokeninfo, which is the only network call on
     * the One Tap path.
     *
     * @param $claims array
     * @return callable the filter, to remove again
     */
    private function withGoogleSaying($claims)
    {
        $stub = function () use ($claims) {
            return [
                'headers'  => [],
                'body'     => wp_json_encode($claims),
                'response' => ['code' => 200, 'message' => 'OK'],
                'cookies'  => []
            ];
        };

        add_filter('pre_http_request', $stub, 10, 1);

        return $stub;
    }

    /**
     * handleGoogleOneTapLogin() terminates through wp_send_json(); capture what it said.
     *
     * @return array
     */
    private function oneTapReplyFor($credential)
    {
        $_POST['credential'] = $credential;

        $die = function () {
            return function ($message = '') {
                throw new \WPDieException((string)$message);
            };
        };

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', $die);

        ob_start();
        try {
            (new \FluentAuth\App\Hooks\Handlers\GoogleOneTapAuthHandler())->handleGoogleOneTapLogin();
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', $die);

        return (array)json_decode($output, true);
    }

    // ------------------------------------------------------------- state token

    public function testAStateTokenValidatesAgainstItself()
    {
        $state = AuthService::setStateToken();

        $this->assertNotEmpty($state);
        $this->assertTrue(AuthService::verifyStateToken($state));
    }

    public function testAWrongOrMissingStateIsRejected()
    {
        AuthService::setStateToken();

        $this->assertFalse(AuthService::verifyStateToken('not-the-state'));
        $this->assertFalse(AuthService::verifyStateToken(''));
        $this->assertFalse(AuthService::verifyStateToken(null));
    }

    public function testStateIsRejectedWhenNoFlowWasStarted()
    {
        unset($_COOKIE['fs_auth_state']);

        $this->assertFalse(AuthService::verifyStateToken('anything'));
    }

    /**
     * A state token covers exactly one callback. Leaving it valid kept the whole
     * callback replayable for as long as the cookie lived.
     */
    public function testStateCannotBeReusedOnceSpent()
    {
        $state = AuthService::setStateToken();
        $this->assertTrue(AuthService::verifyStateToken($state));

        AuthService::clearStateToken();

        $this->assertFalse(AuthService::verifyStateToken($state));
    }

    public function testStateTokensAreUnpredictableAndDistinct()
    {
        $seen = [];

        for ($i = 0; $i < 20; $i++) {
            $state = AuthService::setStateToken();
            $this->assertGreaterThanOrEqual(32, strlen($state));
            $seen[$state] = true;
        }

        $this->assertCount(20, $seen);
    }

    // -------------------------------------------------- google email_verified

    /**
     * Without this, anyone who can attach an address to a Google account could sign in
     * as whichever WordPress user holds that address - an administrator included.
     */
    public function testAGoogleTokenWithAnUnverifiedEmailIsRejected()
    {
        $payload = [
            'aud'            => '1234567890-test.apps.googleusercontent.com',
            'email'          => 'victim@example.test',
            'email_verified' => 'false',
        ];

        $this->assertWpErrorWithCode($this->verifyPayload($payload), 'email_unverified');
    }

    public function testAGoogleTokenWithNoVerifiedClaimAtAllIsRejected()
    {
        $payload = [
            'aud'   => '1234567890-test.apps.googleusercontent.com',
            'email' => 'victim@example.test',
        ];

        $this->assertWpErrorWithCode($this->verifyPayload($payload), 'email_unverified');
    }

    public function testAVerifiedGoogleTokenIsAccepted()
    {
        foreach (['true', true] as $verified) {
            $payload = [
                'aud'            => '1234567890-test.apps.googleusercontent.com',
                'email'          => 'someone@example.test',
                'email_verified' => $verified,
            ];

            $result = $this->verifyPayload($payload);

            $this->assertIsArray($result);
            $this->assertSame('someone@example.test', $result['email']);
        }
    }

    /**
     * A site that has not filled in its client id must not accept anything. The empty
     * configured value and a missing `aud` used to compare equal.
     */
    public function testAnUnconfiguredClientIdAcceptsNothing()
    {
        update_option('__fls_social_auth_settings', [
            'google_key_method' => 'db',
            'google_client_id'  => '',
            'enable_google'     => 'yes',
        ]);
        Helper::resetStatics();

        $payload = ['email' => 'victim@example.test', 'email_verified' => 'true'];

        $this->assertWpErrorWithCode($this->verifyPayload($payload), 'token_error');
    }

    public function testATokenInfoErrorResponseIsRejected()
    {
        $payload = ['error_description' => 'Invalid Value'];

        $this->assertWpErrorWithCode($this->verifyPayload($payload), 'token_error');
    }

    public function testATokenIssuedToADifferentGoogleAppIsRejected()
    {
        $payload = [
            'aud'            => 'somebody-elses-app.apps.googleusercontent.com',
            'email'          => 'someone@example.test',
            'email_verified' => 'true',
        ];

        $this->assertWpErrorWithCode($this->verifyPayload($payload), 'token_error');
    }

    /**
     * Drives verifyClientToken() with a stubbed tokeninfo response.
     */
    private function verifyPayload($payload)
    {
        $stub = function () use ($payload) {
            return [
                'headers'  => [],
                'body'     => wp_json_encode($payload),
                'response' => ['code' => 200, 'message' => 'OK'],
                'cookies'  => [],
                'filename' => null,
            ];
        };

        add_filter('pre_http_request', $stub, 10, 3);
        $result = GoogleAuthService::verifyClientToken('stub.token.value');
        remove_filter('pre_http_request', $stub, 10);

        return $result;
    }

    // ---------------------------------------------------------- open redirect

    public function testOffSiteRedirectTargetsAreRefused()
    {
        $this->assertSame(
            admin_url(),
            Helper::getValidatedRedirectUrl('https://evil.example.com/phish', admin_url())
        );
    }

    public function testOnSiteRedirectTargetsSurvive()
    {
        $onSite = home_url('/welcome');

        $this->assertSame($onSite, Helper::getValidatedRedirectUrl($onSite, admin_url()));
    }

    // ------------------------------------------------- one tap, and what it owes

    /**
     * A brand new account created through One Tap can still owe a second factor, and
     * One Tap answers over AJAX: one_tap.js navigates to `redirect_url` on a success and
     * shows `message` in an alert box on anything else. Sending the challenge as an
     * error told somebody to complete a step while giving them nothing to click, and
     * left them signed out on a site that had just created their account.
     */
    public function testANewOneTapAccountThatOwesAFactorIsSentToTheChallenge()
    {
        update_option('__fls_social_auth_settings', array_merge(
            (array)get_option('__fls_social_auth_settings'),
            ['enabled' => 'yes', 'google_one_tap' => 'yes']
        ));

        /*
         * A device factor, not an emailed code. Google vouching for the address already
         * satisfies email, which is the whole point of getSocialTwoFaRedirect() - an
         * authenticator app is the thing the provider never proved.
         */
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['subscriber'];
        $settings['totp_required_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings);
        update_option('users_can_register', 1);
        update_option('default_role', 'subscriber');
        Helper::resetStatics();

        $stub = $this->withGoogleSaying([
            'aud'            => '1234567890-test.apps.googleusercontent.com',
            'email'          => 'one.tap.newcomer@example.org',
            'email_verified' => 'true',
            'name'           => 'One Tap Newcomer'
        ]);

        try {
            $reply = $this->oneTapReplyFor('an-id-token');
        } finally {
            remove_filter('pre_http_request', $stub, 10);
        }

        $user = get_user_by('email', 'one.tap.newcomer@example.org');

        $this->assertInstanceOf('WP_User', $user, 'precondition: the account was created');

        $pending = flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->first();

        $this->assertNotNull($pending, 'precondition: a challenge was raised for it');
        $this->assertSame(0, get_current_user_id(), 'precondition: and no session was granted');

        $this->assertArrayNotHasKey('message', $reply, 'an alert box is not a way forward');
        $this->assertArrayHasKey('redirect_url', $reply);
        $this->assertStringContainsString($pending->login_hash, $reply['redirect_url']);
    }

    /**
     * And a real failure still reads as one - the redirect is for the case where the
     * sign in worked and only the second step is outstanding.
     */
    public function testAOneTapFailureIsStillAnError()
    {
        update_option('__fls_social_auth_settings', array_merge(
            (array)get_option('__fls_social_auth_settings'),
            ['enabled' => 'yes', 'google_one_tap' => 'yes']
        ));
        Helper::resetStatics();

        // The audience Google reports is somebody else's site.
        $stub = $this->withGoogleSaying([
            'aud'            => 'a-different-site.apps.googleusercontent.com',
            'email'          => 'someone@example.org',
            'email_verified' => 'true'
        ]);

        try {
            $reply = $this->oneTapReplyFor('an-id-token');
        } finally {
            remove_filter('pre_http_request', $stub, 10);
        }

        $this->assertArrayHasKey('message', $reply);
        $this->assertArrayNotHasKey('redirect_url', $reply);
    }

    /**
     * Social login carries where the visitor was going in the `fs_intent_redirect`
     * cookie rather than in $_REQUEST, so the challenge has to be handed it explicitly.
     * getSocialTwoFaRedirect() does, and makeLogin() - the path a brand new account
     * takes - did not, which put everybody who signed up with a provider and owed a
     * factor on the dashboard instead of the page they had clicked the button from.
     */
    public function testANewSocialAccountKeepsWhereItWasGoing()
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['subscriber'];
        $settings['totp_required_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $intended = home_url('/members/checkout/');
        $_COOKIE['fs_intent_redirect'] = rawurlencode($intended);

        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);

        Helper::setSatisfiedFactors(['idp', 'email']);
        $signedIn = AuthService::makeLogin($user, 'google');

        unset($_COOKIE['fs_intent_redirect']);

        $this->assertTrue(is_wp_error($signedIn), 'precondition: a factor is still owed');

        $pending = flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->first();

        $this->assertNotNull($pending);
        $this->assertSame($intended, $pending->redirect_intend);
    }

    /**
     * And with no such cookie the challenge works it out from the request, as it does
     * for every other caller - passing an empty intent would have thrown that away.
     */
    public function testWithoutThatCookieTheRequestStillDecides()
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['subscriber'];
        $settings['totp_required_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        unset($_COOKIE['fs_intent_redirect']);
        $_REQUEST['redirect_to'] = home_url('/account/');

        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);

        try {
            AuthService::makeLogin($user, 'google');
        } finally {
            unset($_REQUEST['redirect_to']);
        }

        $pending = flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->first();

        $this->assertNotNull($pending);
        $this->assertSame(home_url('/account/'), $pending->redirect_intend);
    }

    /**
     * The intent cookie lives an hour and nothing clears it, so an abandoned social
     * login leaves it lying around. Read on a passkey or a signup an hour later it sent
     * that person wherever the social flow had been heading, over the top of the
     * redirect their own request asked for.
     */
    public function testAnAbandonedSocialIntentDoesNotSteerALaterLogin()
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['subscriber'];
        $settings['totp_required_roles'] = ['subscriber'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        // Left behind by a social login nobody finished.
        $_COOKIE['fs_intent_redirect'] = rawurlencode(home_url('/checkout/'));
        $_REQUEST['redirect_to'] = home_url('/my-account/');

        $user = $this->factory->user->create_and_get(['role' => 'subscriber']);

        try {
            // No provider: a passkey, or the auto login after signing up.
            AuthService::makeLogin($user);
        } finally {
            unset($_COOKIE['fs_intent_redirect'], $_REQUEST['redirect_to']);
        }

        $pending = flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->first();

        $this->assertNotNull($pending);
        $this->assertSame(home_url('/my-account/'), $pending->redirect_intend);
    }
}
