<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\WebAuthn\AuthenticatorData;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Cbor;
use FluentAuth\App\Services\TwoFa\WebAuthn\CoseKey;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * The parsing and key handling underneath the ceremonies.
 */
class WebAuthnCoreTest extends BaseTestCase
{
    public function test_base64url_round_trips_arbitrary_bytes()
    {
        for ($length = 0; $length < 40; $length++) {
            $bytes = $length ? random_bytes($length) : '';
            $encoded = Base64Url::encode($bytes);

            $this->assertStringNotContainsString('=', $encoded);
            $this->assertStringNotContainsString('+', $encoded);
            $this->assertStringNotContainsString('/', $encoded);

            if ($length) {
                $this->assertSame($bytes, Base64Url::decode($encoded));
            }
        }
    }

    public function test_base64url_refuses_input_it_cannot_decode_exactly()
    {
        // Standard base64 alphabet, padding, whitespace and an impossible length.
        $this->assertFalse(Base64Url::decode('ab+c'));
        $this->assertFalse(Base64Url::decode('abcd='));
        $this->assertFalse(Base64Url::decode('ab cd'));
        $this->assertFalse(Base64Url::decode('a'));
        $this->assertFalse(Base64Url::decode(''));
    }

    public function test_cbor_reads_the_structures_webauthn_uses()
    {
        $bytes = random_bytes(64);

        $encoded = WebAuthnFixture::cborMap([
            'fmt'      => WebAuthnFixture::cborText('none'),
            'attStmt'  => WebAuthnFixture::cborMap([]),
            'authData' => WebAuthnFixture::cborBytes($bytes)
        ]);

        $decoded = Cbor::decode($encoded);

        $this->assertSame('none', $decoded['fmt']);
        $this->assertSame([], $decoded['attStmt']);
        $this->assertSame($bytes, $decoded['authData']);
    }

    public function test_cbor_reads_negative_integer_labels()
    {
        $encoded = WebAuthnFixture::cborMap([
            -1   => WebAuthnFixture::cborInt(1),
            -257 => WebAuthnFixture::cborInt(-7)
        ]);

        $decoded = Cbor::decode($encoded);

        $this->assertSame(1, $decoded[-1]);
        $this->assertSame(-7, $decoded[-257]);
    }

    /**
     * A duplicate key is where one structure can mean two things - the reason this is
     * refused rather than resolved last-one-wins.
     */
    public function test_cbor_refuses_a_duplicate_map_key()
    {
        $encoded = "\xa2"
            . WebAuthnFixture::cborText('authData') . WebAuthnFixture::cborBytes('first')
            . WebAuthnFixture::cborText('authData') . WebAuthnFixture::cborBytes('second');

        $this->expectException(WebAuthnException::class);
        Cbor::decode($encoded);
    }

    public function test_cbor_refuses_trailing_bytes()
    {
        $this->expectException(WebAuthnException::class);
        Cbor::decode(WebAuthnFixture::cborInt(1) . 'left over');
    }

    public function test_cbor_refuses_truncated_input()
    {
        $this->expectException(WebAuthnException::class);
        Cbor::decode("\x58\x20" . random_bytes(4));
    }

    public function test_cbor_refuses_deep_nesting()
    {
        $nested = WebAuthnFixture::cborInt(1);

        for ($i = 0; $i < 20; $i++) {
            $nested = "\x81" . $nested;
        }

        $this->expectException(WebAuthnException::class);
        Cbor::decode($nested);
    }

    public function test_cbor_refuses_indefinite_lengths_and_tags()
    {
        foreach (["\x5f", "\xbf", "\xc0", "\xfb"] as $unsupported) {
            try {
                Cbor::decode($unsupported . "\x00");
                $this->fail('Accepted an unsupported major type or length');
            } catch (WebAuthnException $e) {
                $this->assertNotEmpty($e->getMessage());
            }
        }
    }

    public function test_es256_key_matches_what_openssl_would_have_written()
    {
        $fixture = new WebAuthnFixture();
        $key = CoseKey::fromCbor($fixture->getCosePublicKey());

        $this->assertSame(CoseKey::ES256, $key->getAlgorithm());
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $key->getPem());
        $this->assertNotFalse(openssl_pkey_get_public($key->getPem()));
    }

    public function test_rs256_key_is_readable_by_openssl()
    {
        $fixture = new WebAuthnFixture('example.org', 'https://example.org', CoseKey::RS256);
        $key = CoseKey::fromCbor($fixture->getCosePublicKey());

        $this->assertSame(CoseKey::RS256, $key->getAlgorithm());
        $this->assertNotFalse(openssl_pkey_get_public($key->getPem()));
    }

    /**
     * EdDSA is refused on purpose - OpenSSL cannot verify it here, and an authenticator
     * that registered one would produce assertions this site could never check.
     */
    public function test_eddsa_is_refused()
    {
        $cose = WebAuthnFixture::cborMap([
            1  => WebAuthnFixture::cborInt(1),
            3  => WebAuthnFixture::cborInt(-8),
            -1 => WebAuthnFixture::cborInt(6),
            -2 => WebAuthnFixture::cborBytes(random_bytes(32))
        ]);

        $this->expectException(WebAuthnException::class);
        CoseKey::fromCbor($cose);
    }

    public function test_short_p256_coordinates_are_refused()
    {
        $cose = WebAuthnFixture::cborMap([
            1  => WebAuthnFixture::cborInt(2),
            3  => WebAuthnFixture::cborInt(-7),
            -1 => WebAuthnFixture::cborInt(1),
            -2 => WebAuthnFixture::cborBytes(random_bytes(31)),
            -3 => WebAuthnFixture::cborBytes(random_bytes(32))
        ]);

        $this->expectException(WebAuthnException::class);
        CoseKey::fromCbor($cose);
    }

    public function test_authenticator_data_reads_the_attested_credential_block()
    {
        $fixture = new WebAuthnFixture();
        $response = $fixture->createRegistrationResponse();

        $attestation = Cbor::decode(Base64Url::decode($response['attestationObject']));
        $authData = new AuthenticatorData($attestation['authData']);

        $this->assertTrue($authData->isUserPresent());
        $this->assertTrue($authData->isUserVerified());
        $this->assertSame($fixture->credentialId, $authData->getCredentialId());
        $this->assertSame(hash('sha256', 'example.org', true), $authData->getRpIdHash());
        $this->assertNotEmpty($authData->getCredentialPublicKey());
    }

    public function test_authenticator_data_refuses_a_short_buffer()
    {
        $this->expectException(WebAuthnException::class);
        new AuthenticatorData(random_bytes(20));
    }

    /**
     * Bytes past the end of the structure are covered by the signature but understood
     * by nobody, which is how one buffer comes to mean different things to different
     * readers.
     */
    public function test_authenticator_data_refuses_trailing_bytes()
    {
        $bare = hash('sha256', 'example.org', true) . chr(0x05) . pack('N', 1);

        $this->expectException(WebAuthnException::class);
        new AuthenticatorData($bare . 'extra');
    }

    public function test_authenticator_data_refuses_an_out_of_range_credential_length()
    {
        $header = hash('sha256', 'example.org', true)
            . chr(AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA)
            . pack('N', 0);

        $body = str_repeat("\0", 16) . pack('n', 2000) . random_bytes(40);

        $this->expectException(WebAuthnException::class);
        new AuthenticatorData($header . $body);
    }
}
