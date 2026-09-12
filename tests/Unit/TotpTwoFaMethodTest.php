<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\AuthFactor;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;

/**
 * An authenticator app is the one factor a compromised mailbox does not hand over, so
 * these tests care about two things: that the code checking is strict, and that the
 * dispatcher never lets another route around it.
 */
class TotpTwoFaMethodTest extends BaseTestCase
{
    private $method;

    private $user;

    private $secret;

    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_login_hashes");

        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = ['administrator'];
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['administrator'];
        $settings['totp_required_roles'] = [];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->method = new TotpTwoFaMethod();
        $this->user = $this->factory->user->create_and_get(['role' => 'administrator']);
        $this->secret = TotpProvider::generateSecret();
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/2fa_methods');
        remove_all_filters('fluent_auth/totp_enabled');
        remove_all_filters('fluent_auth/2fa_challenge_required');
        TwoFaService::resetMethods();
        parent::tearDown();
    }

    private function enroll()
    {
        TotpTwoFaMethod::activate($this->user, $this->secret);
    }

    private function currentCode($offset = 0)
    {
        return TotpProvider::getCodeForCounter(
            $this->secret,
            (int)floor(time() / TotpProvider::PERIOD) + $offset
        );
    }

    public function testItProvesADeviceRatherThanAMailbox()
    {
        $this->assertSame(AuthFactor::DEVICE, $this->method->getSatisfiedFactor());
    }

    public function testItOnlyAppliesToUsersWhoHaveEnrolled()
    {
        $this->assertFalse($this->method->isAvailableForUser($this->user));

        $this->enroll();

        $this->assertTrue($this->method->isAvailableForUser($this->user));
    }

    public function testActivationClearsThePendingSecret()
    {
        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($this->user);

        $this->assertNotEmpty($pending);
        $this->assertSame($pending, TotpTwoFaMethod::getPendingSecret($this->user));

        TotpTwoFaMethod::activate($this->user, $pending);

        $this->assertSame('', TotpTwoFaMethod::getPendingSecret($this->user));
        $this->assertSame($pending, TotpTwoFaMethod::getSecret($this->user));
    }

    /**
     * An abandoned setup must not leave the account demanding codes from an app that
     * was never actually paired.
     */
    public function testAPendingSecretAloneDoesNotEnrollAnyone()
    {
        TotpTwoFaMethod::getOrCreatePendingSecret($this->user);

        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->user));
        $this->assertFalse($this->method->isAvailableForUser($this->user));
    }

    public function testItAcceptsACurrentCode()
    {
        $this->enroll();

        $this->assertTrue($this->method->verifyProof($this->user, null, [
            'login_passcode' => $this->currentCode()
        ]));
    }

    public function testItRejectsAWrongCode()
    {
        $this->enroll();

        $this->assertFalse($this->method->verifyProof($this->user, null, [
            'login_passcode' => '000000'
        ]));
    }

    /**
     * A wrong code has to be a plain false, not a WP_Error: only false counts against
     * the attempt cap, and an attacker guessing must be capped.
     */
    public function testAWrongCodeCountsAgainstTheAttemptCap()
    {
        $this->enroll();

        $result = $this->method->verifyProof($this->user, null, ['login_passcode' => '123456']);

        $this->assertNotWPError($result);
        $this->assertFalse($result);
    }

    public function testAnEmptySubmissionIsAHardFailureNotAGuess()
    {
        $this->enroll();

        $this->assertWPError($this->method->verifyProof($this->user, null, ['login_passcode' => '']));
    }

    public function testTheSameCodeCannotBeUsedTwice()
    {
        $this->enroll();

        $code = $this->currentCode();

        $this->assertTrue($this->method->verifyProof($this->user, null, ['login_passcode' => $code]));

        $this->assertFalse(
            $this->method->verifyProof($this->user, null, ['login_passcode' => $code]),
            'A code stays live for its whole drift window; spending the step is what stops a replay.'
        );
    }

    public function testAUserWhoIsNotEnrolledCannotVerify()
    {
        $this->assertWPError($this->method->verifyProof($this->user, null, [
            'login_passcode' => $this->currentCode()
        ]));
    }

    public function testARecoveryCodeWorksOnceWhenTheDeviceIsGone()
    {
        $this->enroll();

        $codes = TotpTwoFaMethod::generateRecoveryCodes($this->user);

        $this->assertCount(TotpTwoFaMethod::RECOVERY_CODE_COUNT, $codes);
        $this->assertSame(TotpTwoFaMethod::RECOVERY_CODE_COUNT, TotpTwoFaMethod::getRemainingRecoveryCount($this->user));

        $this->assertTrue($this->method->verifyProof($this->user, null, ['login_passcode' => $codes[3]]));

        $this->assertSame(
            TotpTwoFaMethod::RECOVERY_CODE_COUNT - 1,
            TotpTwoFaMethod::getRemainingRecoveryCount($this->user)
        );

        $this->assertFalse(
            $this->method->verifyProof($this->user, null, ['login_passcode' => $codes[3]]),
            'A spent recovery code must not work again.'
        );
    }

    public function testARecoveryCodeIsAcceptedHoweverItIsTyped()
    {
        $this->enroll();

        $codes = TotpTwoFaMethod::generateRecoveryCodes($this->user);

        $typed = strtolower(substr($codes[0], 0, 5) . '-' . substr($codes[0], 5));

        $this->assertTrue($this->method->verifyProof($this->user, null, ['login_passcode' => $typed]));
    }

    public function testRegeneratingRecoveryCodesInvalidatesTheOldSet()
    {
        $this->enroll();

        $old = TotpTwoFaMethod::generateRecoveryCodes($this->user);
        TotpTwoFaMethod::generateRecoveryCodes($this->user);

        $this->assertFalse($this->method->verifyProof($this->user, null, ['login_passcode' => $old[0]]));
    }

    public function testDisablingRemovesEverything()
    {
        $this->enroll();
        TotpTwoFaMethod::generateRecoveryCodes($this->user);

        TotpTwoFaMethod::disable($this->user);

        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->user));
        $this->assertSame(0, TotpTwoFaMethod::getRemainingRecoveryCount($this->user));
        $this->assertSame('', TotpTwoFaMethod::getSecret($this->user));
        $this->assertSame('', TotpTwoFaMethod::getActivatedAt($this->user));
        $this->assertSame('', TotpTwoFaMethod::getPendingSecret($this->user));

        // Not merely unreadable through the accessors - the row itself is gone.
        $this->assertEmpty(get_user_meta($this->user->ID, TotpTwoFaMethod::META_DATA, true));
        $this->assertEmpty(get_user_meta($this->user->ID, TotpTwoFaMethod::META_SECRET, true));
    }

    /**
     * The hazard that keeps every field of an enrollment in one row: a recovery code
     * outliving the secret it was issued alongside. An administrator turns off a lost
     * phone, the user pairs a new one, and a code from the old set still opens the
     * account - past both the new authenticator and the reset that was supposed to have
     * closed it.
     */
    public function testARecoveryCodeDoesNotSurviveAResetAndReEnrollment()
    {
        $this->enroll();
        $old = TotpTwoFaMethod::generateRecoveryCodes($this->user);

        TotpTwoFaMethod::disable($this->user);

        $this->secret = TotpProvider::generateSecret();
        $this->enroll();

        $this->assertFalse(
            $this->method->verifyProof($this->user, null, ['login_passcode' => $old[0]]),
            'A recovery code from before the reset must not work against the new enrollment.'
        );
    }

    /**
     * Whether the account is under attack costs two queries over the auth log, and for a
     * user with an authenticator app enrolled it cannot change the answer - the app is
     * what they will be asked for either way. So it must not be measured at all.
     */
    public function testAnEnrolledUserIsNotMeasuredForAnAttackThatCannotChangeTheOutcome()
    {
        $this->enroll();

        $asked = 0;

        add_filter('fluent_auth/2fa_challenge_required', function ($required) use (&$asked) {
            $asked++;

            return $required;
        }, 10, 2);

        $handler = new TwoFaHandler();
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('totp', $row->use_type);
        $this->assertSame(0, $asked, 'An enrolled user must not be measured against the attack threshold.');
    }

    /**
     * The other side of it: where the answer is recorded, it is still asked for. An
     * emailed code distinguishes a challenge from an ordinary one, and the row has to
     * say which it was or it cannot authorise itself at verify time.
     */
    public function testAChallengeIsStillMeasuredForAMethodThatRecordsIt()
    {
        $asked = 0;

        add_filter('fluent_auth/2fa_challenge_required', function ($required) use (&$asked) {
            $asked++;

            return true;
        }, 10, 2);

        $handler = new TwoFaHandler();
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('2fa_challenge', $row->use_type);
        $this->assertSame(1, $asked, 'The answer is recorded here, so it has to be measured - once.');
    }

    /**
     * The whole reason the method exists: a mailbox does not substitute for a device.
     */
    public function testAnEnrolledUserIsAskedForTheAppEvenAfterAMagicLink()
    {
        $this->enroll();

        Helper::setSatisfiedFactors([AuthFactor::EMAIL]);

        $handler = new TwoFaHandler();
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('totp', $row->use_type);
    }

    public function testAnEnrolledUserIsAskedForTheAppEvenAfterSocialLogin()
    {
        $this->enroll();

        Helper::setSatisfiedFactors([AuthFactor::IDP, AuthFactor::EMAIL]);

        $handler = new TwoFaHandler();
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $this->assertNotFalse($return);

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('totp', $row->use_type);
    }

    /**
     * Both apply to a password login, and the app is the stronger of the two.
     */
    public function testTheAppIsPreferredOverAnEmailedCode()
    {
        $this->enroll();

        $handler = new TwoFaHandler();
        $return = $handler->sendAndGet2FaConfirmFormUrl($this->user, 'both');

        $row = flsDb()->table('fls_login_hashes')->where('login_hash', $return['login_hash'])->first();

        $this->assertSame('totp', $row->use_type);
    }

    /**
     * The dangerous case. A challenge is raised for accounts under attack regardless of
     * what is switched on, and picking a method the user never enrolled in would present
     * a form nobody can answer - locking out the very account being defended.
     */
    public function testAnUnenrolledUserIsNeverChallengedWithTheApp()
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

        $this->assertSame(
            TwoFaHandler::CHALLENGE_USE_TYPE,
            $row->use_type,
            'An unenrolled user must fall back to the emailed code, not the app.'
        );

        remove_filter('fluent_auth/2fa_challenge_required', '__return_true');
    }

    public function testTheMethodCanBeTurnedOffSiteWide()
    {
        $this->enroll();

        add_filter('fluent_auth/totp_enabled', '__return_false');

        $this->assertFalse($this->method->isAvailableForUser($this->user));
    }

    public function testTheFormPostsThroughTheSharedLoginFlow()
    {
        $html = $this->method->renderForm([
            'login_hash'  => 'abc123',
            'redirect_to' => ''
        ]);

        // The login page JS binds to these, so a method that renames them dead ends.
        $this->assertStringContainsString('id="fls_2fa_form"', $html);
        $this->assertStringContainsString('id="fls_2fa_confirm"', $html);
        $this->assertStringContainsString('name="login_passcode"', $html);
        $this->assertStringContainsString('abc123', $html);
    }
}
