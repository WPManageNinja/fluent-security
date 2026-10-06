<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * A COSE public key, turned into something OpenSSL will verify with.
 *
 * An authenticator hands over its public key as a COSE_Key map - raw curve
 * coordinates for an elliptic curve key, raw modulus and exponent for an RSA one.
 * OpenSSL wants a SubjectPublicKeyInfo. The conversion is pure ASN.1 assembly with no
 * arithmetic in it, which is why this package needs no big-number library: for P-256
 * it is a fixed 26 byte prefix in front of the uncompressed point, and the result is
 * byte for byte what OpenSSL itself would have produced for the same key.
 *
 * Two algorithms are accepted and the rest are refused:
 *
 *   ES256 (-7)   universal. Every platform authenticator and every FIDO2 key does it.
 *   RS256 (-257) for TPM backed Windows Hello credentials, which historically used it.
 *
 * EdDSA (-8) is deliberately absent. OpenSSL cannot verify it without libsodium, and
 * WordPress.org strips the same algorithm from its own registration options because
 * Android's NFC stack fails on keys that carry it - so supporting it would mean taking
 * on a dependency in order to enable a combination that is known to break.
 *
 * The PEM is what gets stored, not the COSE bytes. A credential is verified on every
 * login and registered once, so the parsing belongs at the end that happens once; it
 * also means a stored credential stays verifiable even if this parser is later made
 * stricter.
 */
class CoseKey
{
    const ES256 = -7;

    const RS256 = -257;

    const KTY_EC2 = 2;

    const KTY_RSA = 3;

    const CURVE_P256 = 1;

    /**
     * The SubjectPublicKeyInfo header for an uncompressed P-256 point: the ecPublicKey
     * and prime256v1 identifiers, then a 66 byte BIT STRING holding the 0x04 marker and
     * the two 32 byte coordinates. Fixed, because every field in it is fixed.
     */
    const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /** @var string */
    private $pem;

    /** @var int */
    private $algorithm;

    /**
     * @param $pem string
     * @param $algorithm int
     */
    private function __construct($pem, $algorithm)
    {
        $this->pem = $pem;
        $this->algorithm = $algorithm;
    }

    /**
     * @param $pem string
     * @param $algorithm int
     * @return self
     */
    public static function fromStored($pem, $algorithm)
    {
        return new self((string)$pem, (int)$algorithm);
    }

    /**
     * @param $cborBytes string the credentialPublicKey field of authenticator data
     * @return self
     * @throws WebAuthnException
     */
    public static function fromCbor($cborBytes)
    {
        $key = Cbor::decode($cborBytes);

        if (!is_array($key)) {
            throw new WebAuthnException('COSE key is not a map');
        }

        $kty = isset($key[1]) ? $key[1] : null;
        $alg = isset($key[3]) ? $key[3] : null;

        if ($alg !== self::ES256 && $alg !== self::RS256) {
            throw new WebAuthnException('Unsupported COSE algorithm ' . var_export($alg, true));
        }

        if ($alg === self::ES256) {
            if ($kty !== self::KTY_EC2) {
                throw new WebAuthnException('ES256 key is not an EC2 key');
            }

            return new self(self::buildEc2Pem($key), self::ES256);
        }

        if ($kty !== self::KTY_RSA) {
            throw new WebAuthnException('RS256 key is not an RSA key');
        }

        return new self(self::buildRsaPem($key), self::RS256);
    }

    /**
     * @return string
     */
    public function getPem()
    {
        return $this->pem;
    }

    /**
     * @return int
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * Checks a signature made by the matching private key.
     *
     * The signature is used exactly as the authenticator produced it. An ECDSA
     * signature in WebAuthn is already ASN.1 DER, which is the encoding OpenSSL
     * expects, so there is no repacking step and therefore no place to get one wrong.
     *
     * @param $signedData string
     * @param $signature string
     * @return bool
     * @throws WebAuthnException
     */
    public function verify($signedData, $signature)
    {
        if (!function_exists('openssl_verify')) {
            throw new WebAuthnException('The OpenSSL extension is required to verify a passkey');
        }

        if ($signature === '' || $this->pem === '') {
            return false;
        }

        $publicKey = openssl_pkey_get_public($this->pem);

        if (!$publicKey) {
            throw new WebAuthnException('Stored passkey public key could not be read');
        }

        $result = openssl_verify($signedData, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        /*
         * openssl_verify answers 1, 0 or -1, and only 1 is a good signature. Treating
         * this as a boolean would turn -1, which means the check could not be carried
         * out at all, into a pass.
         */
        return $result === 1;
    }

    /**
     * @param $key array
     * @return string
     * @throws WebAuthnException
     */
    private static function buildEc2Pem($key)
    {
        $curve = isset($key[-1]) ? $key[-1] : null;
        $x = isset($key[-2]) ? $key[-2] : null;
        $y = isset($key[-3]) ? $key[-3] : null;

        if ($curve !== self::CURVE_P256) {
            throw new WebAuthnException('Unsupported COSE curve ' . var_export($curve, true));
        }

        /*
         * Exactly 32 bytes each, not "at most". A short coordinate would otherwise be
         * left padded into a different, valid point further down, and the length of the
         * BIT STRING in the prefix above is a constant that assumes this.
         */
        if (!is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
            throw new WebAuthnException('P-256 coordinates must be 32 bytes each');
        }

        return self::toPem(hex2bin(self::P256_SPKI_PREFIX) . "\x04" . $x . $y);
    }

    /**
     * @param $key array
     * @return string
     * @throws WebAuthnException
     */
    private static function buildRsaPem($key)
    {
        $modulus = isset($key[-1]) ? $key[-1] : null;
        $exponent = isset($key[-2]) ? $key[-2] : null;

        if (!is_string($modulus) || !is_string($exponent) || $modulus === '' || $exponent === '') {
            throw new WebAuthnException('RSA key is missing its modulus or exponent');
        }

        // Anything below 2048 bits is not something to accept as a new credential.
        if (strlen($modulus) < 256) {
            throw new WebAuthnException('RSA modulus is too small');
        }

        $publicKey = self::derSequence(
            self::derInteger($modulus) . self::derInteger($exponent)
        );

        $algorithm = self::derSequence(
            // OID 1.2.840.113549.1.1.1, rsaEncryption, then the required NULL parameters.
            hex2bin('06092a864886f70d010101') . "\x05\x00"
        );

        return self::toPem(
            self::derSequence($algorithm . self::derBitString($publicKey))
        );
    }

    /**
     * @param $contents string
     * @return string
     */
    private static function derSequence($contents)
    {
        return "\x30" . self::derLength(strlen($contents)) . $contents;
    }

    /**
     * @param $contents string
     * @return string
     */
    private static function derBitString($contents)
    {
        // The leading zero is the count of unused bits in the final byte, always none here.
        $contents = "\x00" . $contents;

        return "\x03" . self::derLength(strlen($contents)) . $contents;
    }

    /**
     * @param $bytes string an unsigned big-endian integer
     * @return string
     */
    private static function derInteger($bytes)
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        // DER integers are signed, so a leading high bit has to be pushed clear of the sign.
        if (ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    /**
     * @param $length int
     * @return string
     */
    private static function derLength($length)
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * @param $der string
     * @return string
     */
    private static function toPem($der)
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }
}
