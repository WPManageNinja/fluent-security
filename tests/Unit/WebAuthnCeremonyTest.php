<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\WebAuthn\AuthenticatorData;
use FluentAuth\App\Services\TwoFa\WebAuthn\Assertion;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\CoseKey;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\UserHandle;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * The verification checklists from WebAuthn sections 7.1 and 7.2.
 *
 * Every security relevant step gets a test that breaks exactly that step and expects a
 * refusal. A checklist is only worth anything if each line is load bearing, and the way
 * to find a line that is not is to remove it and see whether anything notices.
 */
class WebAuthnCeremonyTest extends BaseTestCase
{
    /** @var WebAuthnFixture */
    private $authenticator;

    /** @var string */
    private $challenge;

    public function setUp(): void
    {
        parent::setUp();

        // The relying party is derived from the site address, which has to be secure.
        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        $this->authenticator = new WebAuthnFixture();
        $this->challenge = random_bytes(32);
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/webauthn_user_verification');
        remove_all_filters('fluent_auth/webauthn_allowed_origins');
        parent::tearDown();
    }

    // ---------------------------------------------------------------- registration

    public function test_a_good_registration_yields_a_storable_credential()
    {
        $response = $this->authenticator->createRegistrationResponse(['challenge' => $this->challenge]);

        $verified = Registration::verify($response, $this->challenge);

        $this->assertSame(Base64Url::encode($this->authenticator->credentialId), $verified['credential_id']);
        $this->assertSame(CoseKey::ES256, $verified['algorithm']);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $verified['public_key']);
        $this->assertSame(1, $verified['user_verified']);
    }

    public function test_registration_refuses_a_challenge_this_site_did_not_issue()
    {
        $response = $this->authenticator->createRegistrationResponse(['challenge' => random_bytes(32)]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_a_foreign_origin()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'origin'    => 'https://example.org.attacker.test'
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    /**
     * The ceremony type is the only thing separating a registration from an assertion.
     */
    public function test_registration_refuses_client_data_from_the_other_ceremony()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'type'      => 'webauthn.get'
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_a_cross_origin_ceremony()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge'   => $this->challenge,
            'crossOrigin' => true
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_another_relying_party()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'rpId'      => 'attacker.test'
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_a_ceremony_with_nobody_present()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    /**
     * User presence has its own test because user verification is required by default
     * and would otherwise be the check that fires - leaving the presence check covered
     * by nothing. The flags are independent bits, and nothing stops a hostile client
     * setting the second without the first.
     */
    public function test_registration_refuses_verification_without_presence()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_USER_VERIFIED
                | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_an_absent_user_even_when_verification_is_optional()
    {
        add_filter('fluent_auth/webauthn_user_verification', function () {
            return 'discouraged';
        });

        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_an_unverified_user_while_verification_is_required()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_a_site_may_lower_the_verification_requirement()
    {
        add_filter('fluent_auth/webauthn_user_verification', function () {
            return 'preferred';
        });

        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
        ]);

        $verified = Registration::verify($response, $this->challenge);

        $this->assertSame(0, $verified['user_verified']);
    }

    /**
     * The id the browser reports and the id the authenticator signed are two separate
     * fields, and only the second is covered by the attestation.
     */
    public function test_registration_refuses_a_reported_id_that_was_not_the_attested_one()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'rawId'     => random_bytes(32)
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_registration_refuses_an_impossible_backup_state()
    {
        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_USER_PRESENT
                | AuthenticatorData::FLAG_USER_VERIFIED
                | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
                | AuthenticatorData::FLAG_BACKED_UP
        ]);

        $this->expectException(WebAuthnException::class);
        Registration::verify($response, $this->challenge);
    }

    public function test_a_site_may_name_a_second_origin()
    {
        add_filter('fluent_auth/webauthn_allowed_origins', function ($origins) {
            $origins[] = 'https://www.example.org';
            return $origins;
        });

        $response = $this->authenticator->createRegistrationResponse([
            'challenge' => $this->challenge,
            'origin'    => 'https://www.example.org'
        ]);

        $verified = Registration::verify($response, $this->challenge);

        $this->assertNotEmpty($verified['public_key']);
    }

    // ------------------------------------------------------------------ assertion

    public function test_a_good_assertion_verifies_and_reports_its_counter()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'signCount' => 7
        ]);

        $this->assertSame(7, Assertion::verify($response, $credential, $this->challenge, $user));
    }

    public function test_an_rs256_credential_verifies()
    {
        $this->authenticator = new WebAuthnFixture('example.org', 'https://example.org', CoseKey::RS256);

        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'signCount' => 3
        ]);

        $this->assertSame(3, Assertion::verify($response, $credential, $this->challenge, $user));
    }

    public function test_assertion_refuses_a_tampered_signature()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'tamper'    => true
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    /**
     * An assertion captured once must not work twice. The challenge is the only thing
     * that makes it single use.
     */
    public function test_assertion_refuses_a_replay_against_a_fresh_challenge()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse(['challenge' => $this->challenge]);

        $this->assertSame(1, Assertion::verify($response, $credential, $this->challenge, $user));

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, random_bytes(32), $user);
    }

    public function test_assertion_refuses_a_foreign_origin()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'origin'    => 'https://phishing.example.net'
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_refuses_another_relying_party()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'rpId'      => 'phishing.example.net'
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_refuses_a_registration_presented_as_a_login()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'type'      => 'webauthn.create'
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_refuses_a_credential_belonging_to_someone_else()
    {
        $owner = $this->makeUser();
        $other = $this->makeUser();
        $credential = $this->register($owner);

        $response = $this->authenticator->createAssertionResponse(['challenge' => $this->challenge]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $other);
    }

    public function test_assertion_refuses_a_reply_that_names_a_different_credential()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'rawId'     => random_bytes(32)
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_accepts_a_matching_user_handle()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);
        $handle = UserHandle::getOrCreate($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge'  => $this->challenge,
            'userHandle' => $handle
        ]);

        $this->assertSame(1, Assertion::verify($response, $credential, $this->challenge, $user));
    }

    public function test_assertion_refuses_a_user_handle_for_another_account()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);
        UserHandle::getOrCreate($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge'  => $this->challenge,
            'userHandle' => random_bytes(64)
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_refuses_verification_without_presence()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_USER_VERIFIED
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_refuses_an_absent_user_even_when_verification_is_optional()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        add_filter('fluent_auth/webauthn_user_verification', function () {
            return 'discouraged';
        });

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'flags'     => 0
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    public function test_assertion_refuses_an_unverified_user_while_verification_is_required()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'flags'     => AuthenticatorData::FLAG_USER_PRESENT
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    /**
     * A counter that stands still or goes backwards is what a cloned authenticator
     * looks like from the server's side.
     */
    public function test_assertion_refuses_a_counter_that_did_not_advance()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);
        $credential->sign_count = 9;

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'signCount' => 9
        ]);

        $this->expectException(WebAuthnException::class);
        Assertion::verify($response, $credential, $this->challenge, $user);
    }

    /**
     * Synced passkeys report zero forever, on purpose. Treating that as a clone would
     * lock out most of the people this feature exists for.
     */
    public function test_a_synced_passkey_reporting_no_counter_is_accepted()
    {
        $user = $this->makeUser();
        $credential = $this->register($user);
        $credential->sign_count = 0;

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => $this->challenge,
            'signCount' => 0
        ]);

        $this->assertSame(0, Assertion::verify($response, $credential, $this->challenge, $user));
    }

    // ----------------------------------------------------------------- scaffolding

    /**
     * @return \WP_User
     */
    private function makeUser()
    {
        return get_user_by('ID', $this->factory->user->create());
    }

    /**
     * Registers the fixture's credential and returns it in the shape the store holds.
     *
     * @param $user \WP_User
     * @return object
     */
    private function register($user)
    {
        $challenge = random_bytes(32);
        $response = $this->authenticator->createRegistrationResponse(['challenge' => $challenge]);
        $verified = Registration::verify($response, $challenge);

        return (object)[
            'id'            => 1,
            'user_id'       => $user->ID,
            'credential_id' => $verified['credential_id'],
            'public_key'    => $verified['public_key'],
            'algorithm'     => $verified['algorithm'],
            'sign_count'    => 0,
            'transports'    => ''
        ];
    }
}
