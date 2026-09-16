<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TotpSetupPageHandler;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

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
}
