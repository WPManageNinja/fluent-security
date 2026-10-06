<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\PasskeyProfileHandler;
use FluentAuth\App\Hooks\Handlers\TotpProfileHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaProfileHandler;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;

/**
 * The second factor card on the profile screen, and the two requests behind its buttons.
 *
 * The interesting cases are all about who is looking. One person's profile can be opened
 * by two people with different authority over it, and the asymmetry - an administrator
 * may take a device off an account but never put one on it - is the one thing this
 * screen must not get wrong in either direction.
 */
class TwoFaProfileScreenTest extends BaseTestCase
{
    /** @var TotpProfileHandler */
    private $totp;

    /** @var TwoFaProfileHandler */
    private $screen;

    /** @var WebAuthnFixture */
    private $authenticator;

    public function setUp(): void
    {
        parent::setUp();

        $_REQUEST = [];

        // Passkeys are refused outright over plain http - see RelyingParty.
        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        PasskeyStore::ensureTable();

        $this->totp = new TotpProfileHandler();
        $this->screen = new TwoFaProfileHandler();
        $this->authenticator = new WebAuthnFixture();

        $this->setSettings([
            'totp_2fa'            => 'yes',
            'totp_2fa_roles'      => ['administrator'],
            'totp_required_roles' => [],
            'passkey_2fa'         => 'yes',
            'passkey_2fa_roles'   => ['administrator'],
            'email2fa'            => 'no'
        ]);

        $_POST = [];
    }

    public function tearDown(): void
    {
        $_POST = [];
        $_REQUEST = [];
        wp_set_current_user(0);
        TwoFaService::resetMethods();
        parent::tearDown();
    }

    // ------------------------------------------------------ turning a factor off

    /**
     * The lost phone path. It is the one thing on this screen an administrator may do to
     * somebody else's account, and the reason the screen exists for them at all.
     */
    public function test_an_administrator_can_turn_off_another_users_authenticator_app()
    {
        $owner = $this->makeAdmin();
        $admin = $this->makeAdmin();

        $this->enrolApp($owner);

        $this->actAs($admin);

        $response = $this->call([$this->totp, 'handleDisableRequest'], ['user_id' => $owner->ID]);

        $this->assertTrue($response['success']);
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($owner->ID));
    }

    public function test_somebody_who_cannot_edit_the_account_cannot_turn_its_factor_off()
    {
        $owner = $this->makeAdmin();
        $other = get_user_by('ID', $this->factory->user->create(['role' => 'author']));

        $this->enrolApp($owner);

        $this->actAs($other);

        $response = $this->call([$this->totp, 'handleDisableRequest'], ['user_id' => $owner->ID]);

        $this->assertFalse($response['success']);
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($owner->ID));
    }

    public function test_a_bad_nonce_turns_nothing_off()
    {
        $owner = $this->makeAdmin();

        $this->enrolApp($owner);

        wp_set_current_user($owner->ID);
        $_POST['_fls_totp_nonce'] = 'not-a-nonce';
        $_REQUEST['_fls_totp_nonce'] = 'not-a-nonce';

        $this->call([$this->totp, 'handleDisableRequest'], ['user_id' => $owner->ID], false);

        $this->assertTrue(TotpTwoFaMethod::isEnrolled($owner->ID));
    }

    // --------------------------------------------------------- recovery codes

    /**
     * They are shown at the moment they are made and never again, so an administrator
     * pressing this for somebody else would be the only person who ever saw that
     * account's way back in.
     */
    public function test_recovery_codes_cannot_be_generated_for_another_account()
    {
        $owner = $this->makeAdmin();
        $admin = $this->makeAdmin();

        $this->enrolApp($owner);
        $before = RecoveryCodes::generate($owner->ID);

        $this->actAs($admin);

        $response = $this->call([$this->totp, 'handleRecoveryRequest'], ['user_id' => $owner->ID]);

        $this->assertFalse($response['success']);
        $this->assertTrue(RecoveryCodes::consume($owner, $before[0]));
    }

    /**
     * Codes on their own protect nothing: they are the escape from a device factor, so
     * without one there is nothing for them to be an escape from.
     */
    public function test_recovery_codes_are_refused_when_the_account_holds_no_device()
    {
        $user = $this->makeAdmin();

        $this->actAs($user);

        $response = $this->call([$this->totp, 'handleRecoveryRequest'], []);

        $this->assertFalse($response['success']);
        $this->assertSame(0, RecoveryCodes::countRemaining($user->ID));
    }

    public function test_replacing_the_codes_hands_back_a_set_and_retires_the_old_one()
    {
        $user = $this->makeAdmin();

        $this->enrolApp($user);
        $before = RecoveryCodes::generate($user->ID);

        $this->actAs($user);

        $response = $this->call([$this->totp, 'handleRecoveryRequest'], []);

        $this->assertTrue($response['success']);
        $this->assertCount(RecoveryCodes::CODE_COUNT, $response['data']['codes']);

        $this->assertFalse(RecoveryCodes::consume($user, $before[0]));
        $this->assertTrue(RecoveryCodes::consume($user, $response['data']['codes'][0]));
    }

    /**
     * A passkey holder may never have been given a set, and hasFallback() counts these
     * codes - so refusing them here would leave the account reading as recoverable on
     * the strength of something nobody has.
     */
    public function test_a_passkey_holder_can_draw_codes_without_an_authenticator_app()
    {
        $user = $this->makeAdmin();

        $this->enrolPasskey($user);

        $this->actAs($user);

        $response = $this->call([$this->totp, 'handleRecoveryRequest'], []);

        $this->assertTrue($response['success']);
        $this->assertSame(RecoveryCodes::CODE_COUNT, RecoveryCodes::countRemaining($user->ID));
    }

    // ---------------------------------------------------------------- the card

    public function test_nothing_is_drawn_for_a_user_no_method_is_offered_to()
    {
        $this->setSettings([
            'totp_2fa'          => 'no',
            'passkey_2fa'       => 'no',
            'passkey_2fa_roles' => [],
            'email2fa'          => 'no'
        ]);

        $user = get_user_by('ID', $this->factory->user->create(['role' => 'subscriber']));

        $this->actAs($user);

        $this->assertSame('', trim($this->render($user)));
    }

    /**
     * Adding a factor for somebody else would mean pairing a device they do not hold to
     * an account that is not yours. The card has to offer an administrator every removal
     * and no enrolment at all.
     */
    public function test_an_administrator_gets_the_removals_and_none_of_the_enrolments()
    {
        $owner = $this->makeAdmin();
        $admin = $this->makeAdmin();

        $this->enrolApp($owner);
        $this->enrolPasskey($owner);

        $this->actAs($admin);

        $html = $this->renderMarkup($owner);

        $this->assertStringContainsString('data-fls2fa-totp-disable', $html);
        $this->assertStringContainsString('data-fls2fa-passkey-remove', $html);

        $this->assertStringNotContainsString('data-fls2fa-open', $html);
        $this->assertStringNotContainsString('fls_totp_confirm_code', $html);
        $this->assertStringNotContainsString('data-fls2fa-recovery', $html);
    }

    /**
     * The secret is drawn on the screen, so a profile opened by anybody but its owner
     * must not so much as generate one.
     */
    public function test_no_pending_secret_is_created_by_an_administrator_looking_on()
    {
        $owner = $this->makeAdmin();
        $admin = $this->makeAdmin();

        $this->actAs($admin);
        $this->render($owner);

        $this->assertSame('', TotpTwoFaMethod::getPendingSecret($owner->ID));
    }

    public function test_the_account_holder_is_offered_both_ways_in()
    {
        $user = $this->makeAdmin();

        $this->actAs($user);

        $html = $this->renderMarkup($user);

        $this->assertStringContainsString('data-fls2fa-open="fls2fa-totp"', $html);
        $this->assertStringContainsString('data-fls2fa-open="fls2fa-passkey"', $html);
        $this->assertStringContainsString('fls_totp_confirm_code', $html);
    }

    /**
     * A single passkey with nothing behind it is registered and never asked for - see
     * PasskeyTwoFaMethod::hasFallback(). Reporting it as active is how somebody ends up
     * believing an account is protected by a device that is not in the login flow.
     */
    public function test_a_lone_passkey_is_not_reported_as_active()
    {
        $user = $this->makeAdmin();

        $this->enrolPasskey($user);

        $this->actAs($user);

        $html = $this->renderMarkup($user);

        $this->assertStringContainsString('Not in use', $html);
        $this->assertStringNotContainsString('>Active<', preg_replace('#\s+#', '', $html));
    }

    /**
     * The way out of the dormant state, offered on the same card that reports it. This
     * row used to be hidden from precisely the account that needed it, because a lone
     * passkey does not count as a device factor the login flow can use.
     */
    public function test_a_lone_passkey_is_still_offered_recovery_codes()
    {
        $user = $this->makeAdmin();

        $this->enrolPasskey($user);

        $this->actAs($user);

        $html = $this->renderMarkup($user);

        $this->assertStringContainsString('data-fls2fa-recovery', $html);
        $this->assertStringContainsString('Recovery codes', $html);
    }

    // ------------------------------------------------- registering a passkey here

    /**
     * Drives handleRegister() the way the browser does, and returns the notice it leaves
     * behind - which is how any minted codes reach the screen, since the page reloads
     * after a registration and they are shown exactly once.
     *
     * @param $user \WP_User
     * @param $label string
     * @return array|false
     */
    private function registerPasskey($user, $label = 'Touch ID')
    {
        $challenge = random_bytes(32);

        set_transient(
            PasskeyProfileHandler::CHALLENGE_TRANSIENT . $user->ID,
            Base64Url::encode($challenge),
            PasskeyProfileHandler::CHALLENGE_TTL
        );

        /*
         * A fresh authenticator per call, because each call is a different device - the
         * laptop and then the phone. One WebAuthnFixture holds one credential id for its
         * lifetime, so reusing the shared instance presents the same credential twice and
         * PasskeyStore::add() rightly refuses the duplicate.
         */
        $device = new WebAuthnFixture();

        $this->call([new PasskeyProfileHandler(), 'handleRegister'], [
            '_fls_passkey_nonce' => wp_create_nonce(PasskeyProfileHandler::NONCE_ACTION),
            'label'              => $label,
            'transports'         => json_encode(['internal']),
            'response'           => wp_slash(json_encode(
                $device->createRegistrationResponse(['challenge' => $challenge])
            ))
        ], false);

        return TotpProfileHandler::pullNotice($user->ID);
    }

    /**
     * The user's report, in one test: set up a fingerprint and nothing else.
     *
     * The passkey registered and hasFallback() refused it, so the login flow never asked
     * for it - and a required user still owed a factor after doing exactly what the screen
     * told them to. Which is the worst shape a failure can take, because it looks like it
     * worked. Reported from 3.0.1 on 2026-09-18.
     */
    public function test_a_lone_passkey_is_given_the_codes_that_make_it_count()
    {
        $user = $this->makeAdmin();
        $this->actAs($user);

        $notice = $this->registerPasskey($user);

        $this->assertSame(1, PasskeyStore::countForUser($user));
        $this->assertTrue(
            PasskeyTwoFaMethod::hasFallback($user),
            'A passkey the login flow will never ask for is not a second factor.'
        );
        $this->assertGreaterThan(0, RecoveryCodes::countRemaining($user));

        // Shown once, so they have to arrive on the notice the reload picks up.
        $this->assertSame('codes', $notice['type']);
        $this->assertNotEmpty($notice['codes']);
    }

    /**
     * The consequence the report was actually about.
     */
    public function test_registering_a_fingerprint_settles_a_requirement()
    {
        $user = $this->makeAdmin();
        $this->setSettings(['totp_required_roles' => ['administrator'], 'two_fa_required_level' => 'device']);
        $this->actAs($user);

        $this->assertTrue(
            DeviceRequirement::isOwedBy($user),
            'The premise: a requirement they have not met.'
        );

        $this->registerPasskey($user);

        $this->assertFalse(
            DeviceRequirement::isOwedBy($user),
            'Registering a fingerprint has to settle the requirement it was set up for.'
        );
    }

    /**
     * Somebody adding their phone alongside their laptop still holds the set printed last
     * time, and replacing it silently would retire codes they have filed somewhere.
     */
    public function test_a_second_passkey_leaves_the_existing_codes_alone()
    {
        $user = $this->makeAdmin();
        $this->actAs($user);

        $this->registerPasskey($user, 'Laptop');
        $before = RecoveryCodes::countRemaining($user);

        $notice = $this->registerPasskey($user, 'Phone');

        $this->assertSame(2, PasskeyStore::countForUser($user));
        $this->assertSame($before, RecoveryCodes::countRemaining($user));
        $this->assertFalse($notice, 'Nothing was minted, so there is nothing to announce.');
    }

    /**
     * An authenticator app is a fallback of its own - it can be answered by typing - so a
     * passkey registered behind one is usable at once and needs nothing minted.
     */
    public function test_a_passkey_behind_an_authenticator_app_mints_nothing()
    {
        $user = $this->makeAdmin();
        $this->enrolApp($user);
        RecoveryCodes::clear($user->ID);
        $this->actAs($user);

        $notice = $this->registerPasskey($user);

        $this->assertTrue(PasskeyTwoFaMethod::hasFallback($user));
        $this->assertSame(0, RecoveryCodes::countRemaining($user));
        $this->assertFalse($notice);
    }

    public function test_a_registration_answering_the_wrong_challenge_mints_nothing()
    {
        $user = $this->makeAdmin();
        $this->actAs($user);

        set_transient(
            PasskeyProfileHandler::CHALLENGE_TRANSIENT . $user->ID,
            Base64Url::encode(random_bytes(32)),
            PasskeyProfileHandler::CHALLENGE_TTL
        );

        $this->call([new PasskeyProfileHandler(), 'handleRegister'], [
            '_fls_passkey_nonce' => wp_create_nonce(PasskeyProfileHandler::NONCE_ACTION),
            'response'           => wp_slash(json_encode(
                $this->authenticator->createRegistrationResponse(['challenge' => random_bytes(32)])
            ))
        ], false);

        $this->assertSame(0, PasskeyStore::countForUser($user));
        $this->assertSame(0, RecoveryCodes::countRemaining($user));
    }

    /**
     * The buttons are ajax, so a browser that ran no script would otherwise have no way
     * to turn a factor off at all. These two fields are what
     * TotpProfileHandler::handleUpdate() reads on save.
     */
    public function test_the_no_script_fallback_still_carries_the_two_switches()
    {
        $user = $this->makeAdmin();

        $this->enrolApp($user);

        $this->actAs($user);

        $html = $this->renderMarkup($user);

        $this->assertStringContainsString('<noscript>', $html);
        $this->assertStringContainsString('name="fls_totp_disable"', $html);
        $this->assertStringContainsString('name="fls_totp_regenerate_recovery"', $html);
    }

    // ----------------------------------------------------------------- helpers

    /**
     * @param $user \WP_User
     * @return string
     */
    private function render($user)
    {
        ob_start();
        $this->screen->render($user);

        return (string)ob_get_clean();
    }

    /**
     * The card without its stylesheet and its script, both of which name every selector
     * on the screen whether or not the control using it was drawn.
     *
     * @param $user \WP_User
     * @return string
     */
    private function renderMarkup($user)
    {
        return (string)preg_replace(
            '#<(style|script)\b[^>]*>.*?</\1>#s',
            '',
            $this->render($user)
        );
    }

    /**
     * The ajax handlers end the request through wp_send_json(); capture what they said.
     *
     * @param $callback callable
     * @param $payload array
     * @param $withNonce bool
     * @return array
     */
    private function call($callback, $payload, $withNonce = true)
    {
        foreach ($payload as $key => $value) {
            $_POST[$key] = $value;
        }

        if ($withNonce) {
            $_POST['_fls_totp_nonce'] = wp_create_nonce(TotpProfileHandler::NONCE_ACTION);
        }

        // check_ajax_referer() reads $_REQUEST, which php builds for a real request.
        $_REQUEST = array_merge($_REQUEST, $_POST);

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        ob_start();

        try {
            call_user_func($callback);
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }

        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        $decoded = json_decode($output, true);

        return is_array($decoded) ? $decoded : ['success' => false, 'data' => []];
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    private function actAs($user)
    {
        wp_set_current_user($user->ID);
    }

    /**
     * @return \WP_User
     */
    private function makeAdmin()
    {
        return get_user_by('ID', $this->factory->user->create(['role' => 'administrator']));
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    private function enrolApp($user)
    {
        $secret = TotpProvider::generateSecret();

        TotpTwoFaMethod::activate($user->ID, $secret);
    }

    /**
     * @param $user \WP_User
     * @param $label string
     * @return void
     */
    private function enrolPasskey($user, $label = 'Test key')
    {
        $challenge = random_bytes(32);
        $response = $this->authenticator->createRegistrationResponse(['challenge' => $challenge]);

        PasskeyStore::add($user, Registration::verify($response, $challenge), $label);
    }

    /**
     * @param $settings array
     * @return void
     */
    private function setSettings($settings)
    {
        update_option('__fls_auth_settings', array_merge(
            (array)get_option('__fls_auth_settings'),
            $settings
        ));

        Helper::resetStatics();
    }
}
