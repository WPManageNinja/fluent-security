<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\PasskeyLoginHandler;
use FluentAuth\App\Http\Controllers\SettingsController;
use FluentAuth\App\Services\TwoFa\AuthFactor;
use FluentAuth\App\Services\TwoFa\PasskeyLogin;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\UserHandle;

/**
 * Signing in with a passkey and no password.
 *
 * The thing under test that the second factor flow never has to think about is that
 * nobody has said who they are: the account has to come out of the assertion, and every
 * rule that normally runs on the `authenticate` chain has to be applied here instead.
 */
class PasskeyLoginTest extends BaseTestCase
{
    /** @var WebAuthnFixture */
    private $authenticator;

    public function setUp(): void
    {
        parent::setUp();

        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        PasskeyStore::ensureTable();

        $this->authenticator = new WebAuthnFixture();

        $this->setSettings([
            'passkey_2fa'           => 'yes',
            'passkey_2fa_roles'     => ['administrator'],
            'passkey_primary_login' => 'yes'
        ]);
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/passkey_primary_login');
        remove_all_filters('fluent_auth/device_factor_completes_login');
        remove_all_filters('fluent_auth/passkey_enabled');
        wp_set_current_user(0);
        TwoFaService::resetMethods();
        parent::tearDown();
    }

    // ------------------------------------------------------------ when it is offered

    public function test_the_login_button_is_off_until_it_is_switched_on()
    {
        $this->setSettings(['passkey_primary_login' => 'no']);

        $this->assertFalse(PasskeyLogin::isPrimaryLoginEnabled());
    }

    public function test_the_login_button_needs_passkeys_switched_on_as_well()
    {
        $this->setSettings(['passkey_2fa' => 'no']);

        $this->assertFalse(PasskeyLogin::isPrimaryLoginEnabled());
    }

    public function test_a_site_can_withdraw_the_button_through_the_filter()
    {
        add_filter('fluent_auth/passkey_primary_login', '__return_false');

        $this->assertFalse(PasskeyLogin::isPrimaryLoginEnabled());
    }

    public function test_it_is_offered_once_both_switches_are_on()
    {
        $this->assertTrue(PasskeyLogin::isPrimaryLoginEnabled());
    }

    // ------------------------------------------------------------------- the challenge

    public function test_the_challenge_names_no_credentials()
    {
        $issued = PasskeyLogin::issueChallenge();

        $this->assertIsArray($issued);
        $this->assertNotEmpty($issued['token']);

        /*
         * The whole difference from the second factor ceremony. A list here would mean
         * the site had already decided whose passkey may answer, which it cannot have
         * done - nobody has said who they are yet.
         */
        $this->assertSame([], $issued['options']['allowCredentials']);
        $this->assertSame('example.org', $issued['options']['rpId']);
    }

    public function test_no_challenge_is_issued_while_the_button_is_off()
    {
        $this->setSettings(['passkey_primary_login' => 'no']);

        $this->assertWPError(PasskeyLogin::issueChallenge());
    }

    // ------------------------------------------------------------------ signing in

    public function test_a_passkey_signs_its_owner_in_without_a_username()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $signedIn = PasskeyLogin::authenticate(...$this->assertionFor($user));

        $this->assertInstanceOf(\WP_User::class, $signedIn);
        $this->assertEquals($user->ID, $signedIn->ID);
        $this->assertEquals($user->ID, get_current_user_id());
    }

    public function test_a_passkey_login_declares_the_factors_it_proved()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        PasskeyLogin::authenticate(...$this->assertionFor($user));

        $factors = Helper::getSatisfiedFactors();

        $this->assertContains(AuthFactor::DEVICE, $factors);

        // User verification is required by default, so the gesture was checked too.
        $this->assertContains(AuthFactor::KNOWLEDGE, $factors);
    }

    public function test_the_audit_log_names_the_route_in()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        PasskeyLogin::authenticate(...$this->assertionFor($user));

        // 'web' would read as the password form, which is the one thing it was not.
        $this->assertSame('passkey_login', Helper::getLoginMedia());
        $this->assertSame('Passkey (no password)', Helper::getLoginMediaLabel('passkey_login'));
    }

    public function test_a_handle_the_authenticator_volunteers_must_be_the_owners()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $handle = UserHandle::getOrCreate($user);

        $issued = PasskeyLogin::issueChallenge();
        $response = $this->authenticator->createAssertionResponse([
            'challenge'  => $this->challengeBytes($issued),
            'userHandle' => $handle
        ]);

        $this->assertInstanceOf(
            \WP_User::class,
            PasskeyLogin::authenticate($issued['token'], $response)
        );
    }

    public function test_a_handle_belonging_to_somebody_else_is_refused()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        UserHandle::getOrCreate($user);
        $stranger = UserHandle::getOrCreate($this->makeUser('administrator'));

        $issued = PasskeyLogin::issueChallenge();
        $response = $this->authenticator->createAssertionResponse([
            'challenge'  => $this->challengeBytes($issued),
            'userHandle' => $stranger
        ]);

        $this->assertWPError(PasskeyLogin::authenticate($issued['token'], $response));
        $this->assertSame(0, get_current_user_id());
    }

    // ------------------------------------------------------------------ what is refused

    public function test_a_challenge_can_only_be_spent_once()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $issued = PasskeyLogin::issueChallenge();
        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challengeBytes($issued)
        ]);

        $this->assertInstanceOf(\WP_User::class, PasskeyLogin::authenticate($issued['token'], $response));

        wp_set_current_user(0);

        // The same assertion replayed is the attack the challenge exists to stop.
        $this->assertWPError(PasskeyLogin::authenticate($issued['token'], $response));
        $this->assertSame(0, get_current_user_id());
    }

    public function test_a_token_nobody_issued_is_refused()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $response = $this->authenticator->createAssertionResponse(['challenge' => random_bytes(32)]);

        $this->assertWPError(PasskeyLogin::authenticate('not-a-real-token', $response));
    }

    public function test_a_credential_this_site_does_not_know_is_refused()
    {
        $this->makeUser('administrator');

        $issued = PasskeyLogin::issueChallenge();
        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challengeBytes($issued)
        ]);

        // Never registered, so there is no public key to check the signature against.
        $this->assertWPError(PasskeyLogin::authenticate($issued['token'], $response));
        $this->assertSame(0, get_current_user_id());
    }

    public function test_a_tampered_signature_is_refused()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $issued = PasskeyLogin::issueChallenge();
        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challengeBytes($issued),
            'tamper'    => true
        ]);

        $this->assertWPError(PasskeyLogin::authenticate($issued['token'], $response));
        $this->assertSame(0, get_current_user_id());
    }

    public function test_the_refusal_never_says_which_check_failed()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        // A credential this site has never seen, from an authenticator of its own.
        $stranger = new WebAuthnFixture();
        $issued = PasskeyLogin::issueChallenge();
        $unknown = PasskeyLogin::authenticate($issued['token'], $stranger->createAssertionResponse([
            'challenge' => $this->challengeBytes($issued)
        ]));

        // A credential this site does know, answering with a signature that is not its own.
        $issued = PasskeyLogin::issueChallenge();
        $tampered = PasskeyLogin::authenticate($issued['token'], $this->authenticator->createAssertionResponse([
            'challenge' => $this->challengeBytes($issued),
            'tamper'    => true
        ]));

        $this->assertWPError($unknown);
        $this->assertWPError($tampered);

        /*
         * An unregistered credential and a bad signature have to read identically, or
         * the login form answers "is this passkey registered here" for anyone who asks.
         */
        $this->assertSame($unknown->get_error_message(), $tampered->get_error_message());
        $this->assertSame($unknown->get_error_code(), $tampered->get_error_code());
    }

    public function test_a_valid_assertion_is_refused_once_the_button_is_switched_off()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $issued = PasskeyLogin::issueChallenge();
        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challengeBytes($issued)
        ]);

        $this->setSettings(['passkey_primary_login' => 'no']);

        $this->assertWPError(PasskeyLogin::authenticate($issued['token'], $response));
        $this->assertSame(0, get_current_user_id());
    }

    public function test_a_user_the_site_has_stopped_allowing_cannot_sign_in()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        add_filter('fluent_auth/passkey_enabled', '__return_false');

        $this->assertWPError(PasskeyLogin::authenticate(...$this->assertionFor($user)));
        $this->assertSame(0, get_current_user_id());
    }

    // ------------------------------------------------------- the role list is bypassed

    public function test_every_role_may_register_one_while_the_button_is_on()
    {
        $subscriber = $this->makeUser('subscriber');

        // The list names administrators only, and it stops applying.
        $this->assertTrue(PasskeyTwoFaMethod::isAllowedForUser($subscriber));
    }

    public function test_the_role_list_applies_again_once_the_button_is_off()
    {
        $subscriber = $this->makeUser('subscriber');

        $this->setSettings(['passkey_primary_login' => 'no']);

        $this->assertFalse(PasskeyTwoFaMethod::isAllowedForUser($subscriber));
    }

    public function test_a_subscriber_can_sign_in_with_a_passkey()
    {
        $subscriber = $this->makeUser('subscriber');
        $this->enrol($subscriber);

        $signedIn = PasskeyLogin::authenticate(...$this->assertionFor($subscriber));

        $this->assertInstanceOf(\WP_User::class, $signedIn);
        $this->assertEquals($subscriber->ID, $signedIn->ID);
    }

    // ------------------------------------------------- nothing further is owed after it

    public function test_a_passkey_login_is_not_then_asked_for_an_emailed_code()
    {
        $user = $this->makeUser('administrator');

        $this->setSettings([
            'email2fa'       => 'yes',
            'email2fa_roles' => ['administrator']
        ]);

        $owed = TwoFaService::getRequiredMethod($user, [AuthFactor::DEVICE, AuthFactor::KNOWLEDGE]);

        $this->assertNull($owed);
    }

    public function test_a_site_can_still_demand_one_through_the_filter()
    {
        $user = $this->makeUser('administrator');

        $this->setSettings([
            'email2fa'       => 'yes',
            'email2fa_roles' => ['administrator']
        ]);

        add_filter('fluent_auth/device_factor_completes_login', '__return_false');

        $owed = TwoFaService::getRequiredMethod($user, [AuthFactor::DEVICE, AuthFactor::KNOWLEDGE]);

        $this->assertNotNull($owed);
        $this->assertSame(AuthFactor::EMAIL, $owed->getSatisfiedFactor());
    }

    public function test_a_password_login_still_owes_its_second_factor()
    {
        $user = $this->makeUser('administrator');

        $this->setSettings([
            'email2fa'       => 'yes',
            'email2fa_roles' => ['administrator']
        ]);

        // The default set, which is what every password login declares.
        $owed = TwoFaService::getRequiredMethod($user, [AuthFactor::KNOWLEDGE]);

        $this->assertNotNull($owed);
    }

    // ----------------------------------------------------------------- the setting itself

    public function test_the_flag_cannot_outlive_the_method_it_depends_on()
    {
        $saved = $this->saveSettings([
            'passkey_2fa'           => 'no',
            'passkey_primary_login' => 'yes'
        ]);

        $this->assertSame('no', $saved['passkey_primary_login']);
    }

    public function test_the_flag_survives_a_save_while_passkeys_are_on()
    {
        $saved = $this->saveSettings([
            'passkey_2fa'           => 'yes',
            'passkey_primary_login' => 'yes'
        ]);

        $this->assertSame('yes', $saved['passkey_primary_login']);
    }

    // ------------------------------------------------------- where the button is placed

    public function test_the_button_is_hooked_above_the_magic_link_and_social_buttons()
    {
        $handler = new PasskeyLoginHandler();
        $handler->register();

        /*
         * The placement is entirely this number. MagicLoginHandler and SocialAuthHandler
         * take the same two hooks at the default 10, so anything higher here would put
         * the passkey under the magic link rather than above it - which is the one thing
         * about this block anybody would notice changing.
         */
        $this->assertSame(9, has_action('login_form', [$handler, 'maybeRenderOnLoginPage']));
        $this->assertSame(9, has_filter('login_form_bottom', [$handler, 'maybeRenderOnCustomForm']));

        remove_action('login_form', [$handler, 'maybeRenderOnLoginPage'], 9);
        remove_filter('login_form_bottom', [$handler, 'maybeRenderOnCustomForm'], 9);
    }

    public function test_nothing_is_rendered_while_the_button_is_switched_off()
    {
        $this->setSettings(['passkey_primary_login' => 'no']);

        $handler = new PasskeyLoginHandler();

        $this->assertSame('', $handler->maybeRenderOnCustomForm(''));
    }

    public function test_the_block_is_rendered_once_even_on_a_page_holding_two_forms()
    {
        $handler = new PasskeyLoginHandler();

        $first = $handler->maybeRenderOnCustomForm('');
        $second = $handler->maybeRenderOnCustomForm('');

        // Two copies would mean two elements sharing every id the script looks up.
        $this->assertStringContainsString('fls_passkey_login_button', $first);
        $this->assertSame('', $second);
    }

    // ------------------------------------------------------------------------- helpers

    /**
     * @param $role string
     * @return \WP_User
     */
    private function makeUser($role)
    {
        return get_user_by('ID', $this->factory->user->create(['role' => $role]));
    }

    /**
     * @param $user \WP_User
     * @return array
     */
    private function enrol($user)
    {
        $challenge = random_bytes(32);
        $response = $this->authenticator->createRegistrationResponse(['challenge' => $challenge]);
        $verified = Registration::verify($response, $challenge);

        PasskeyStore::add($user, $verified, 'Test key');

        return $verified;
    }

    /**
     * A freshly issued challenge answered by the fixture, as authenticate() wants it.
     *
     * @param $user \WP_User
     * @return array [$token, $response]
     */
    private function assertionFor($user)
    {
        $issued = PasskeyLogin::issueChallenge();

        return [
            $issued['token'],
            $this->authenticator->createAssertionResponse([
                'challenge' => $this->challengeBytes($issued)
            ])
        ];
    }

    /**
     * @param $issued array
     * @return string raw bytes
     */
    private function challengeBytes($issued)
    {
        return \FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url::decode($issued['options']['challenge']);
    }

    /**
     * @param $settings array
     * @return array
     */
    private function setSettings($settings)
    {
        update_option('__fls_auth_settings', array_merge(
            (array)get_option('__fls_auth_settings'),
            $settings
        ));

        Helper::resetStatics();

        return (array)get_option('__fls_auth_settings');
    }

    /**
     * Puts settings through the controller, so the normalising it does is under test.
     *
     * @param $settings array
     * @return array
     */
    private function saveSettings($settings)
    {
        wp_set_current_user($this->factory->user->create(['role' => 'administrator']));

        $request = new \WP_REST_Request('POST', '/fluent-auth/settings');
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), $settings));

        SettingsController::updateSettings($request);

        Helper::resetStatics();

        return Helper::getAuthSettings();
    }

    /**
     * A site that has filtered `device_factor_completes_login` to false still wants a
     * second factor after a passkey, and AuthService::makeLogin() now answers that with
     * a `fls_2fa_required` error carrying the challenge URL. login_helper.js follows
     * `data.redirect` on a success and shows `data.message` on a failure, so handing it
     * the failure shape stranded the very people who had just proved a passkey.
     */
    public function test_a_passkey_that_still_owes_a_factor_is_sent_to_the_challenge()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        $this->setSettings([
            'email2fa'       => 'yes',
            'email2fa_roles' => ['administrator']
        ]);

        add_filter('fluent_auth/device_factor_completes_login', '__return_false');

        list($token, $response) = $this->assertionFor($user);

        $reply = $this->verifyReply($token, $response);

        $pending = flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->first();

        $this->assertNotNull($pending, 'precondition: a challenge was raised');
        $this->assertTrue($reply['success'], 'a raised challenge is a next step, not a refusal');
        $this->assertStringContainsString($pending->login_hash, $reply['data']['redirect']);
    }

    /**
     * And a refusal is still a refusal, with nowhere to go.
     */
    public function test_a_refused_passkey_is_still_an_error()
    {
        $user = $this->makeUser('administrator');
        $this->enrol($user);

        list($token, $response) = $this->assertionFor($user);

        // Spent already, so the second attempt has nothing to check against.
        $this->verifyReply($token, $response);

        $reply = $this->verifyReply($token, $response);

        $this->assertFalse($reply['success']);
        $this->assertArrayNotHasKey('redirect', (array)$reply['data']);
    }

    /**
     * handleVerify() terminates through wp_send_json_*(); capture what it emitted.
     *
     * @return array
     */
    private function verifyReply($token, $response)
    {
        $_POST['_nonce'] = wp_create_nonce(PasskeyLoginHandler::NONCE_ACTION);
        $_POST['token'] = $token;
        $_POST['webauthn_response'] = addslashes(wp_json_encode($response));

        $die = function () {
            return function ($message = '') {
                throw new \WPDieException((string)$message);
            };
        };

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', $die);

        ob_start();
        try {
            (new PasskeyLoginHandler())->handleVerify();
        } catch (\WPDieException $e) {
            // expected: wp_send_json_*() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', $die);

        unset($_POST['_nonce'], $_POST['token'], $_POST['webauthn_response']);

        return (array)json_decode($output, true);
    }
}
