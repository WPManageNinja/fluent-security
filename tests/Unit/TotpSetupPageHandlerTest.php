<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\PasskeyProfileHandler;
use FluentAuth\App\Hooks\Handlers\TotpSetupPageHandler;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;

/**
 * The setup screen outside wp-admin.
 *
 * It exists so members who are kept out of the admin area can still pair an app, which
 * means it is reachable by roles the profile screen never was - so the tests that matter
 * are the ones about what it refuses to do for them.
 */
class TotpSetupPageHandlerTest extends BaseTestCase
{
    private $handler;

    private $user;

    public function setUp(): void
    {
        parent::setUp();

        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['subscriber'];
        $settings['totp_required_roles'] = [];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->handler = new TotpSetupPageHandler();
        $this->user = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $_POST = [];
    }

    public function tearDown(): void
    {
        $_POST = [];
        wp_set_current_user(0);
        parent::tearDown();
    }

    private function actAs($user)
    {
        wp_set_current_user($user->ID);
        $_POST['_fls_totp_nonce'] = wp_create_nonce(TotpSetupPageHandler::NONCE_ACTION);
    }

    private function codeFor($secret)
    {
        return TotpProvider::getCodeForCounter($secret, (int)floor(time() / TotpProvider::PERIOD));
    }

    public function testTheUrlIsOnWpLoginRatherThanWpAdmin()
    {
        $url = TotpSetupPageHandler::getUrl();

        $this->assertStringContainsString('wp-login.php', $url);
        $this->assertStringContainsString('action=' . TotpSetupPageHandler::LOGIN_ACTION, $url);
        $this->assertStringNotContainsString('/wp-admin/', $url);
    }

    /**
     * wp-login.php drops an action it does not recognise back to the login form unless
     * something is listening for it, so the hook is what makes the address work at all.
     */
    public function testRegisteringMakesWpLoginHonourTheAction()
    {
        $this->handler->register();

        $this->assertNotFalse(
            has_action('login_form_' . TotpSetupPageHandler::LOGIN_ACTION),
            'Without a listener wp-login.php falls back to the login screen.'
        );
    }

    /**
     * "Not now" and "Continue" go back to where the user was heading. PHP decodes the
     * query string once on the way in; decoding it again turned `%2F` into `/` and `+`
     * into a space, so a destination carrying an encoded value arrived altered.
     */
    public function testTheDestinationSurvivesTheRoundTripUnchanged()
    {
        $destination = home_url('/members/?ref=a%2Fb+c&next=' . rawurlencode(home_url('/x/?y=1')));

        parse_str((string)wp_parse_url(TotpSetupPageHandler::getUrl($destination, true), PHP_URL_QUERY), $query);
        $_REQUEST = $query;

        $method = new \ReflectionMethod($this->handler, 'getRedirectTo');
        $method->setAccessible(true);

        try {
            $this->assertSame($destination, $method->invoke($this->handler));
        } finally {
            $_REQUEST = [];
        }
    }

    public function testConfirmingTheCodePairsTheApp()
    {
        $this->actAs($this->user);

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_totp_confirm_code'] = $this->codeFor($pending);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertTrue(TotpTwoFaMethod::isEnrolled($this->user->ID));
        $this->assertSame('codes', $notice['type']);
        $this->assertCount(
            TotpTwoFaMethod::RECOVERY_CODE_COUNT,
            $notice['codes'],
            'The codes are shown once, so activation has to hand them back to be shown.'
        );
    }

    public function testAWrongCodePairsNothing()
    {
        $this->actAs($this->user);

        TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_totp_confirm_code'] = '000000';

        $notice = $this->handler->processSubmission($this->user);

        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->user->ID));
        $this->assertSame('error', $notice['type']);
    }

    public function testAMissingNoncePairsNothing()
    {
        wp_set_current_user($this->user->ID);

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_totp_confirm_code'] = $this->codeFor($pending);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->user->ID));
        $this->assertSame('error', $notice['type']);
    }

    /**
     * The screen is open to any signed in user, so the role policy has to be enforced
     * on the submission rather than only by not drawing the form.
     */
    public function testARoleThatIsNotAllowedOneCannotPairFromThisScreen()
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->actAs($this->user);

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_totp_confirm_code'] = $this->codeFor($pending);

        $this->assertFalse($this->handler->processSubmission($this->user));
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->user->ID));
    }

    /**
     * A resubmitted form must not re-pair an account. The second pairing would issue a
     * fresh set of recovery codes and quietly invalidate the set the user just saved.
     */
    public function testAnAccountThatIsAlreadyPairedIsLeftAlone()
    {
        $this->actAs($this->user);

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_totp_confirm_code'] = $this->codeFor($pending);

        $first = $this->handler->processSubmission($this->user);
        $secret = TotpTwoFaMethod::getSecret($this->user->ID);

        $this->assertFalse($this->handler->processSubmission($this->user));
        $this->assertSame($secret, TotpTwoFaMethod::getSecret($this->user->ID));
        $this->assertCount(TotpTwoFaMethod::RECOVERY_CODE_COUNT, $first['codes']);
    }

    /**
     * Setting up is all this screen does - turning an app off stays where an
     * administrator can see it happen.
     */
    public function testItCannotTurnAnAppOff()
    {
        $this->actAs($this->user);

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_totp_confirm_code'] = $this->codeFor($pending);
        $this->handler->processSubmission($this->user);

        $_POST = [
            '_fls_totp_nonce'  => wp_create_nonce(TotpSetupPageHandler::NONCE_ACTION),
            'fls_totp_disable' => 'yes'
        ];

        $this->handler->processSubmission($this->user);

        $this->assertTrue(TotpTwoFaMethod::isEnrolled($this->user->ID));
    }

    /* ------------------------------------------------------------- passkeys */

    /**
     * Passkeys need a secure context, or the method is off whatever the setting says.
     */
    private function enablePasskeys($roles = ['subscriber'])
    {
        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        $settings = Helper::getAuthSettings();
        $settings['passkey_2fa'] = 'yes';
        $settings['passkey_2fa_roles'] = $roles;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function disableTotp()
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function requireOf($roles)
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_required_roles'] = $roles;
        $settings['two_fa_required_level'] = 'device';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    /**
     * Stores a challenge the way drawing the screen would, and hands back the bytes so a
     * fixture authenticator can answer it.
     */
    private function storeChallenge($user)
    {
        $challenge = random_bytes(32);

        set_transient(
            PasskeyProfileHandler::CHALLENGE_TRANSIENT . $user->ID,
            Base64Url::encode($challenge),
            PasskeyProfileHandler::CHALLENGE_TTL
        );

        return $challenge;
    }

    private function passkeyResponse($challenge)
    {
        $authenticator = new WebAuthnFixture();

        return wp_slash(json_encode($authenticator->createRegistrationResponse(['challenge' => $challenge])));
    }

    /**
     * The whole reason this screen grew a second method.
     *
     * With passkeys on and the app off, the page used to tell a required user that an
     * authenticator app was not enabled for their account and offer them a Continue link
     * back to the admin area - which redirected them here again. The way out was the
     * profile screen, which is exactly what this screen's audience cannot reach.
     */
    public function testAPasskeyOnlySiteStillHasSomethingToOffer()
    {
        $this->enablePasskeys();
        $this->disableTotp();
        $this->requireOf(['subscriber']);

        $offer = $this->handler->getOffer($this->user);

        $this->assertTrue($offer['passkey'], 'A passkey is the only route left, so it has to be on offer.');
        $this->assertFalse($offer['app']);
        $this->assertTrue(
            DeviceRequirement::isOwedBy($this->user),
            'The premise of the test: this user is held to a requirement they have not met.'
        );
    }

    public function testBothRoutesAreOfferedWhereBothAreSwitchedOn()
    {
        $this->enablePasskeys();

        $offer = $this->handler->getOffer($this->user);

        $this->assertTrue($offer['app']);
        $this->assertTrue($offer['passkey']);
        $this->assertNotEmpty($offer['secret']);
    }

    public function testNeitherRouteIsOfferedWhereNeitherIsSwitchedOn()
    {
        $this->disableTotp();

        $offer = $this->handler->getOffer($this->user);

        $this->assertFalse($offer['app']);
        $this->assertFalse($offer['passkey']);
        $this->assertFalse($offer['secret_failed'], 'Nothing on offer is a setting, not a server failure.');
    }

    public function testAPasskeyRegistersFromThisScreen()
    {
        $this->enablePasskeys();
        $this->actAs($this->user);

        $challenge = $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse($challenge);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertSame('codes', $notice['type']);
        $this->assertSame(1, PasskeyStore::countForUser($this->user));
    }

    /**
     * The half of the passkey route that is not cosmetic.
     *
     * A lone passkey with nothing behind it fails PasskeyTwoFaMethod::hasFallback(), so
     * the login flow never challenges with it and the requirement is still owed. Without
     * the codes this screen would tell a user they were done and leave them in the exact
     * bounce it exists to end.
     */
    public function testRegisteringAPasskeyMintsTheCodesThatMakeItCount()
    {
        $this->enablePasskeys();
        $this->disableTotp();
        $this->requireOf(['subscriber']);
        $this->actAs($this->user);

        $challenge = $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse($challenge);

        $notice = $this->handler->processSubmission($this->user);

        /*
         * Asserted first, because it is the consequence rather than the mechanism: a
         * passkey that leaves the requirement owed puts the user straight back into the
         * bounce this screen exists to end.
         */
        $this->assertFalse(
            DeviceRequirement::isOwedBy($this->user),
            'The requirement has to actually be met by the end of this, not merely attempted.'
        );
        $this->assertGreaterThan(0, RecoveryCodes::countRemaining($this->user));
        $this->assertNotEmpty(
            Helper::getSetting('totp_required_roles'),
            'The premise: a requirement is in force.'
        );
        $this->assertNotEmpty(
            isset($notice['codes']) ? $notice['codes'] : [],
            'They are shown once, so the notice has to carry them.'
        );
    }

    /**
     * Somebody adding a second device still holds the printed set from last time.
     */
    public function testASecondPasskeyLeavesExistingRecoveryCodesAlone()
    {
        $this->enablePasskeys();
        $this->actAs($this->user);

        $existing = RecoveryCodes::generate($this->user->ID);
        $remaining = RecoveryCodes::countRemaining($this->user);

        $challenge = $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse($challenge);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertNotEmpty($existing);
        $this->assertArrayNotHasKey('codes', $notice, 'Codes nobody asked to replace must not be replaced.');
        $this->assertSame($remaining, RecoveryCodes::countRemaining($this->user));
    }

    public function testAPasskeyAnsweringADifferentChallengeRegistersNothing()
    {
        $this->enablePasskeys();
        $this->actAs($this->user);

        $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse(random_bytes(32));

        $notice = $this->handler->processSubmission($this->user);

        $this->assertSame('error', $notice['type']);
        $this->assertSame(0, PasskeyStore::countForUser($this->user));
    }

    /**
     * Spent on sight, so a failed attempt cannot be retried against the same challenge.
     */
    public function testTheChallengeIsSpentWhetherOrNotItWorked()
    {
        $this->enablePasskeys();
        $this->actAs($this->user);

        $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse(random_bytes(32));

        $this->handler->processSubmission($this->user);

        $this->assertFalse(get_transient(PasskeyProfileHandler::CHALLENGE_TRANSIENT . $this->user->ID));
    }

    public function testAPasskeyIsRefusedWithNoOutstandingChallenge()
    {
        $this->enablePasskeys();
        $this->actAs($this->user);

        $_POST['fls_setup_credential'] = $this->passkeyResponse(random_bytes(32));

        $notice = $this->handler->processSubmission($this->user);

        $this->assertSame('error', $notice['type']);
        $this->assertSame(0, PasskeyStore::countForUser($this->user));
    }

    /**
     * The screen is open to any signed in user, so the policy has to be enforced on the
     * submission rather than only by not drawing the button - the same reason the app
     * route re-checks its own role list.
     */
    public function testARoleThatMayNotHaveAPasskeyCannotRegisterOneHere()
    {
        $this->enablePasskeys(['administrator']);
        $this->actAs($this->user);

        $challenge = $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse($challenge);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertSame('error', $notice['type']);
        $this->assertSame(0, PasskeyStore::countForUser($this->user));
    }

    public function testAMissingNonceRegistersNoPasskeyEither()
    {
        $this->enablePasskeys();
        wp_set_current_user($this->user->ID);

        $challenge = $this->storeChallenge($this->user);
        $_POST['fls_setup_credential'] = $this->passkeyResponse($challenge);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertSame('error', $notice['type']);
        $this->assertSame(0, PasskeyStore::countForUser($this->user));
    }

    /**
     * Which proof arrived decides which route was taken. An empty credential field is
     * posted on every app submission, so it must not be read as a passkey attempt.
     */
    public function testAnEmptyCredentialFieldStillTakesTheAppRoute()
    {
        $this->enablePasskeys();
        $this->actAs($this->user);

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);
        $_POST['fls_setup_credential'] = '';
        $_POST['fls_totp_confirm_code'] = $this->codeFor($pending);

        $notice = $this->handler->processSubmission($this->user);

        $this->assertTrue(TotpTwoFaMethod::isEnrolled($this->user->ID));
        $this->assertSame('codes', $notice['type']);
    }
}
