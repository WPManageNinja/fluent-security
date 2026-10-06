<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;

/**
 * Reversible encryption for the one stored value that has to be read back.
 *
 * Authenticated rather than merely encrypted - AES-256-GCM, whose tag is checked on the
 * way out - so a ciphertext that has been altered fails to decrypt instead of decrypting
 * to something else. That matters more here than it would for a document: a TOTP secret
 * is base32, and a tampered CBC-mode ciphertext could plausibly decode to a valid-looking
 * secret that verifies nobody's codes. GCM turns that into a clean failure.
 *
 * Every ciphertext names the key it was made with:
 *
 *     fa1$<key id>$<base64url iv>$<base64url ciphertext and tag>
 *
 * The prefix is what makes turning this on a non-event. A value without it is plaintext
 * from before encryption was switched on, and is returned as it stands - so there is no
 * moment when half the table is unreadable, and no batch job that has to complete before
 * logins work. The key id is what makes turning it *off*, or re-keying it, possible at
 * all: a row can be recognised as belonging to a key that is no longer in force without
 * first trying and failing to decrypt it.
 */
class SecretCipher
{
    const CIPHER = 'aes-256-gcm';

    const PREFIX = 'fa1';

    const IV_LENGTH = 12;

    const TAG_LENGTH = 16;

    /**
     * Whether a stored value is one of ours rather than plaintext.
     *
     * @param string $value
     * @return bool
     */
    public static function isProtected($value)
    {
        return is_string($value) && strpos($value, self::PREFIX . '$') === 0;
    }

    /**
     * The key id a ciphertext was made with.
     *
     * @param string $value
     * @return string empty for plaintext or a malformed value
     */
    public static function keyIdOf($value)
    {
        if (!self::isProtected($value)) {
            return '';
        }

        $parts = explode('$', $value);

        return isset($parts[1]) ? $parts[1] : '';
    }

    /**
     * @param string $plaintext
     * @param string $key 32 raw bytes
     * @return string the encoded ciphertext, or empty when it could not be made
     */
    public static function protect($plaintext, $key)
    {
        if (!is_string($plaintext) || $plaintext === '' || !is_string($key) || $key === '') {
            return '';
        }

        if (!SecretKey::isSupported()) {
            return '';
        }

        try {
            $iv = random_bytes(self::IV_LENGTH);
        } catch (\Exception $e) {
            return '';
        }

        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            return '';
        }

        return implode('$', [
            self::PREFIX,
            SecretKey::fingerprint($key),
            Base64Url::encode($iv),
            /*
             * Tag stored with the ciphertext rather than in a field of its own. It is
             * fixed width and always present, so splitting it out would be a fourth
             * segment that can only ever be sixteen bytes long.
             */
            Base64Url::encode($ciphertext . $tag)
        ]);
    }

    /**
     * @param string $value plaintext or one of ours
     * @param string $key 32 raw bytes
     * @return string|false false when this value cannot be read with this key
     */
    public static function reveal($value, $key)
    {
        if (!is_string($value) || $value === '') {
            return '';
        }

        /*
         * Not encrypted, so there is nothing to undo. This is the path every row takes on
         * a site that has never switched encryption on, and the path a row takes between
         * being written before the switch and being rewritten after it.
         */
        if (!self::isProtected($value)) {
            return $value;
        }

        if (!is_string($key) || $key === '' || !SecretKey::isSupported()) {
            return false;
        }

        $parts = explode('$', $value);

        if (count($parts) !== 4) {
            return false;
        }

        $iv = Base64Url::decode($parts[2]);
        $payload = Base64Url::decode($parts[3]);

        if ($iv === false || $payload === false) {
            return false;
        }

        if (strlen($iv) !== self::IV_LENGTH || strlen($payload) <= self::TAG_LENGTH) {
            return false;
        }

        $ciphertext = substr($payload, 0, -self::TAG_LENGTH);
        $tag = substr($payload, -self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $plaintext === false ? false : $plaintext;
    }

    /**
     * Encrypts a secret on its way into the table, if encryption is in force.
     *
     * Returns the value unchanged when it is not - which is what lets FactorStore call
     * this unconditionally rather than asking first.
     *
     * @param string $plaintext
     * @return string
     */
    public static function protectForStorage($plaintext)
    {
        if (!is_string($plaintext) || $plaintext === '' || self::isProtected($plaintext)) {
            return (string)$plaintext;
        }

        if (!SecretKey::isEnabled()) {
            return $plaintext;
        }

        $key = SecretKey::current();

        if ($key === '') {
            /*
             * Encryption is on but the key is gone. Writing plaintext here would quietly
             * undo the site's own decision at the worst possible moment, so the value is
             * refused instead and the caller reports a failure - which for an enrollment
             * means "could not be set up", not "set up without protection".
             */
            return '';
        }

        return self::protect($plaintext, $key);
    }

    /**
     * Decrypts a secret on its way out, or reports that it cannot be read.
     *
     * @param string $stored
     * @return string|false
     */
    public static function revealFromStorage($stored)
    {
        if (!self::isProtected($stored)) {
            return is_string($stored) ? $stored : '';
        }

        return self::reveal($stored, SecretKey::current());
    }
}
