<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * The authenticator data structure, which is a fixed binary layout rather than CBOR.
 *
 * Thirty-seven bytes of header - the hash of the relying party id, one byte of flags,
 * a four byte signature counter - and then two optional blocks whose presence is
 * announced by two of those flags. Registration carries the attested credential data
 * block; an ordinary assertion is usually the header alone.
 *
 * The only part that is not a fixed offset is the public key, which is CBOR of
 * unannounced length sitting between the credential id and any extensions. That is why
 * the decoder reports how many bytes it consumed: it is the only thing that says where
 * the key ended.
 */
class AuthenticatorData
{
    const FLAG_USER_PRESENT = 0x01;

    const FLAG_USER_VERIFIED = 0x04;

    const FLAG_BACKUP_ELIGIBLE = 0x08;

    const FLAG_BACKED_UP = 0x10;

    const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    const FLAG_EXTENSION_DATA = 0x80;

    /**
     * The header, before either optional block.
     */
    const HEADER_LENGTH = 37;

    /**
     * Per the specification a credential id is at most 1023 bytes. A length field
     * claiming more is a malformed structure, and reading it would walk off the end of
     * the buffer into whatever follows.
     */
    const MAX_CREDENTIAL_ID_LENGTH = 1023;

    /** @var string */
    private $raw;

    /** @var string */
    private $rpIdHash;

    /** @var int */
    private $flags;

    /** @var int */
    private $signCount;

    /** @var string */
    private $aaguid = '';

    /** @var string */
    private $credentialId = '';

    /** @var string */
    private $credentialPublicKey = '';

    /**
     * @param $bytes string
     * @throws WebAuthnException
     */
    public function __construct($bytes)
    {
        if (!is_string($bytes) || strlen($bytes) < self::HEADER_LENGTH) {
            throw new WebAuthnException('Authenticator data is shorter than its own header');
        }

        $this->raw = $bytes;
        $this->rpIdHash = substr($bytes, 0, 32);
        $this->flags = ord($bytes[32]);

        $counter = unpack('N', substr($bytes, 33, 4));
        $this->signCount = $counter[1];

        // unpack('N') is signed on a 32-bit build, where a high counter would come back negative.
        if ($this->signCount < 0) {
            $this->signCount += 4294967296;
        }

        $offset = self::HEADER_LENGTH;

        if ($this->hasFlag(self::FLAG_ATTESTED_CREDENTIAL_DATA)) {
            $offset = $this->readAttestedCredentialData($bytes, $offset);
        }

        if ($this->hasFlag(self::FLAG_EXTENSION_DATA)) {
            // Parsed only to prove it is well formed and that nothing follows it.
            Cbor::decodeFirst(substr($bytes, $offset), $consumed);
            $offset += $consumed;
        }

        /*
         * Nothing may be left over. Trailing bytes would be data that is covered by the
         * signature but understood by nobody, which is exactly the shape of a structure
         * that means one thing to this parser and another to the next one.
         */
        if ($offset !== strlen($bytes)) {
            throw new WebAuthnException('Trailing bytes after authenticator data');
        }
    }

    /**
     * @param $bytes string
     * @param $offset int
     * @return int the offset just past the block
     * @throws WebAuthnException
     */
    private function readAttestedCredentialData($bytes, $offset)
    {
        if (strlen($bytes) < $offset + 18) {
            throw new WebAuthnException('Attested credential data is truncated');
        }

        $this->aaguid = substr($bytes, $offset, 16);
        $offset += 16;

        $length = unpack('n', substr($bytes, $offset, 2));
        $length = $length[1];
        $offset += 2;

        if ($length < 1 || $length > self::MAX_CREDENTIAL_ID_LENGTH) {
            throw new WebAuthnException('Credential id length is out of range');
        }

        if (strlen($bytes) < $offset + $length) {
            throw new WebAuthnException('Credential id is truncated');
        }

        $this->credentialId = substr($bytes, $offset, $length);
        $offset += $length;

        $remainder = substr($bytes, $offset);

        if ($remainder === '') {
            throw new WebAuthnException('Attested credential data has no public key');
        }

        Cbor::decodeFirst($remainder, $consumed);

        $this->credentialPublicKey = substr($remainder, 0, $consumed);

        return $offset + $consumed;
    }

    /**
     * @param $flag int
     * @return bool
     */
    public function hasFlag($flag)
    {
        return (bool)($this->flags & $flag);
    }

    /**
     * @return string
     */
    public function getRaw()
    {
        return $this->raw;
    }

    /**
     * @return string
     */
    public function getRpIdHash()
    {
        return $this->rpIdHash;
    }

    /**
     * @return int
     */
    public function getSignCount()
    {
        return $this->signCount;
    }

    /**
     * @return string
     */
    public function getAaguid()
    {
        return $this->aaguid;
    }

    /**
     * @return string
     */
    public function getCredentialId()
    {
        return $this->credentialId;
    }

    /**
     * @return string
     */
    public function getCredentialPublicKey()
    {
        return $this->credentialPublicKey;
    }

    /**
     * @return bool
     */
    public function isUserPresent()
    {
        return $this->hasFlag(self::FLAG_USER_PRESENT);
    }

    /**
     * @return bool
     */
    public function isUserVerified()
    {
        return $this->hasFlag(self::FLAG_USER_VERIFIED);
    }

    /**
     * Whether the credential is one a password manager or platform account can copy to
     * the user's other devices - a synced passkey rather than one bound to this
     * hardware. Recorded so an administrator can see it; it is not a pass or fail.
     *
     * @return bool
     */
    public function isBackupEligible()
    {
        return $this->hasFlag(self::FLAG_BACKUP_ELIGIBLE);
    }
}
