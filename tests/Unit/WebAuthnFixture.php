<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\WebAuthn\AuthenticatorData;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\CoseKey;

/**
 * A stand-in authenticator.
 *
 * Builds the same bytes a real one would, signed with a key this class holds, so the
 * verification checklist can be exercised in both directions - a good ceremony that
 * must pass, and a ceremony with exactly one thing wrong that must not.
 *
 * It is not a substitute for a recorded response from real hardware. What it proves is
 * that the checks fire; what it cannot prove is that the structures match what Touch ID
 * or a password manager actually emits. Those live in WebAuthnRecordedFixtureTest,
 * captured from devices rather than generated here.
 */
class WebAuthnFixture
{
    /** @var resource|\OpenSSLAsymmetricKey */
    private $privateKey;

    /** @var string */
    public $credentialId;

    /** @var string */
    public $rpId;

    /** @var string */
    public $origin;

    /** @var int */
    public $algorithm;

    /**
     * @param $rpId string
     * @param $origin string
     * @param $algorithm int
     */
    public function __construct($rpId = 'example.org', $origin = 'https://example.org', $algorithm = CoseKey::ES256)
    {
        $this->rpId = $rpId;
        $this->origin = $origin;
        $this->algorithm = $algorithm;
        $this->credentialId = random_bytes(32);

        $this->privateKey = $algorithm === CoseKey::RS256
            ? openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048])
            : openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    }

    /**
     * The COSE_Key an authenticator would hand over at registration.
     *
     * @return string
     */
    public function getCosePublicKey()
    {
        $details = openssl_pkey_get_details($this->privateKey);

        if ($this->algorithm === CoseKey::RS256) {
            return self::cborMap([
                1  => self::cborInt(CoseKey::KTY_RSA),
                3  => self::cborInt(CoseKey::RS256),
                -1 => self::cborBytes($details['rsa']['n']),
                -2 => self::cborBytes($details['rsa']['e'])
            ]);
        }

        return self::cborMap([
            1  => self::cborInt(CoseKey::KTY_EC2),
            3  => self::cborInt(CoseKey::ES256),
            -1 => self::cborInt(CoseKey::CURVE_P256),
            -2 => self::cborBytes(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            -3 => self::cborBytes(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT))
        ]);
    }

    /**
     * @param $args array challenge, type, origin, rpId, flags, signCount, attested
     * @return array the browser's reply
     */
    public function createRegistrationResponse($args = [])
    {
        $args = array_merge([
            'challenge' => random_bytes(32),
            'origin'    => $this->origin,
            'rpId'      => $this->rpId,
            'flags'     => AuthenticatorData::FLAG_USER_PRESENT
                | AuthenticatorData::FLAG_USER_VERIFIED
                | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA,
            'signCount' => 0,
            'fmt'       => 'none',
            'rawId'     => null
        ], $args);

        $authData = $this->buildAuthData($args['rpId'], $args['flags'], $args['signCount'], true);

        $attestation = self::cborMap([
            'fmt'     => self::cborText($args['fmt']),
            'attStmt' => self::cborMap([]),
            'authData' => self::cborBytes($authData)
        ]);

        return [
            'rawId'             => Base64Url::encode($args['rawId'] === null ? $this->credentialId : $args['rawId']),
            'clientDataJSON'    => Base64Url::encode($this->buildClientData('webauthn.create', $args)),
            'attestationObject' => Base64Url::encode($attestation)
        ];
    }

    /**
     * @param $args array
     * @return array
     */
    public function createAssertionResponse($args = [])
    {
        $args = array_merge([
            'challenge'  => random_bytes(32),
            'origin'     => $this->origin,
            'rpId'       => $this->rpId,
            'flags'      => AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_USER_VERIFIED,
            'signCount'  => 1,
            'userHandle' => '',
            'rawId'      => null,
            'tamper'     => false
        ], $args);

        $authData = $this->buildAuthData($args['rpId'], $args['flags'], $args['signCount'], false);
        $clientDataJson = $this->buildClientData('webauthn.get', $args);

        $signature = '';
        openssl_sign($authData . hash('sha256', $clientDataJson, true), $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        if ($args['tamper']) {
            // Flip a bit inside the signature rather than replacing it, so it stays well formed.
            $signature[10] = chr(ord($signature[10]) ^ 0x01);
        }

        return [
            'rawId'             => Base64Url::encode($args['rawId'] === null ? $this->credentialId : $args['rawId']),
            'clientDataJSON'    => Base64Url::encode($clientDataJson),
            'authenticatorData' => Base64Url::encode($authData),
            'signature'         => Base64Url::encode($signature),
            'userHandle'        => $args['userHandle'] ? Base64Url::encode($args['userHandle']) : ''
        ];
    }

    /**
     * @param $rpId string
     * @param $flags int
     * @param $signCount int
     * @param $attested bool
     * @return string
     */
    private function buildAuthData($rpId, $flags, $signCount, $attested)
    {
        $data = hash('sha256', $rpId, true) . chr($flags) . pack('N', $signCount);

        if ($attested) {
            $key = $this->getCosePublicKey();
            $data .= str_repeat("\0", 16)
                . pack('n', strlen($this->credentialId))
                . $this->credentialId
                . $key;
        }

        return $data;
    }

    /**
     * @param $type string
     * @param $args array
     * @return string
     */
    private function buildClientData($type, $args)
    {
        $clientData = [
            'type'      => isset($args['type']) ? $args['type'] : $type,
            'challenge' => Base64Url::encode($args['challenge']),
            'origin'    => $args['origin']
        ];

        if (!empty($args['crossOrigin'])) {
            $clientData['crossOrigin'] = true;
        }

        return json_encode($clientData);
    }

    // ---- The smallest CBOR encoder that can build these two structures ----

    /**
     * @param $pairs array
     * @return string
     */
    public static function cborMap($pairs)
    {
        $out = self::cborHead(0xa0, count($pairs));

        foreach ($pairs as $key => $value) {
            $out .= is_int($key) ? self::cborInt($key) : self::cborText($key);
            $out .= $value;
        }

        return $out;
    }

    /**
     * @param $value int
     * @return string
     */
    public static function cborInt($value)
    {
        return $value >= 0
            ? self::cborHead(0x00, $value)
            : self::cborHead(0x20, -1 - $value);
    }

    /**
     * @param $bytes string
     * @return string
     */
    public static function cborBytes($bytes)
    {
        return self::cborHead(0x40, strlen($bytes)) . $bytes;
    }

    /**
     * @param $text string
     * @return string
     */
    public static function cborText($text)
    {
        return self::cborHead(0x60, strlen($text)) . $text;
    }

    /**
     * @param $major int
     * @param $value int
     * @return string
     */
    private static function cborHead($major, $value)
    {
        if ($value < 24) {
            return chr($major | $value);
        }

        if ($value < 256) {
            return chr($major | 24) . chr($value);
        }

        if ($value < 65536) {
            return chr($major | 25) . pack('n', $value);
        }

        return chr($major | 26) . pack('N', $value);
    }
}
