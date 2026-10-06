<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * The key that protects an authenticator secret, and whether it is still the same one.
 *
 * A TOTP secret is the one thing this plugin stores that has to be readable back: a code
 * is checked by generating it, so unlike a password or a recovery code there is no hash
 * that would do. That makes it the only row whose confidentiality depends on a key.
 *
 * There is exactly one place that key can come from - a constant in wp-config.php - and a
 * site without one stores its secrets in the clear, as this plugin always did. The obvious
 * second option was to borrow AUTH_SALT, and it is deliberately not offered: rotating the
 * salts is ordinary advice after a compromise, several tools have a button for it, and it
 * would silently take every enrolled authenticator app with it. A key with an expiry date
 * nobody set is worse than no key, because the site believes it is protected. Where the
 * constants are not defined at all, wp_salt() invents them into the options table, so on
 * those installs it would also be a key sitting in the same dump as the ciphertext.
 *
 * Two states, then: keyed, or plaintext. What is stored to tell them apart is the key's
 * fingerprint rather than the key - a canary, being a known string encrypted under it. That
 * is what lets the site notice the key has changed without ever writing it to the database,
 * and say which way it changed, because the recovery differs. See diagnose().
 */
class SecretKey
{
    const CONSTANT = 'FLUENT_AUTH_SECURITY_KEY';

    const STATE_OPTION = '__fls_auth_secret_key_state';

    /* The canary decrypts. Everything is readable. */
    const STATE_OK = 'ok';

    /* Encryption was never switched on, so the secrets are stored as they always were. */
    const STATE_OFF = 'off';

    /* The constant is no longer defined - usually a deploy that overwrote wp-config.php. */
    const STATE_CONSTANT_MISSING = 'constant_missing';

    /* The constant is defined but is not the value these secrets were encrypted with. */
    const STATE_KEY_CHANGED = 'key_changed';

    /*
     * What a canary holds. Any fixed string does; this one is recognisable in a database
     * dump, which saves somebody wondering what the row is for.
     */
    const CANARY_PLAINTEXT = 'fluent-auth/secret-key-canary';

    /**
     * Whether this server can encrypt at all.
     *
     * Asked before anything is offered in the UI, because enabling encryption on a server
     * that cannot do it would write secrets nobody can read back.
     *
     * @return bool
     */
    public static function isSupported()
    {
        return function_exists('openssl_encrypt')
            && function_exists('openssl_decrypt')
            && in_array(SecretCipher::CIPHER, (array)openssl_get_cipher_methods(), true);
    }

    /**
     * The raw key material, before derivation.
     *
     * Filtered, so that a site which keeps its secrets somewhere other than wp-config.php
     * - a Bedrock install reading .env, or a host with a key management service - can
     * supply the key without the plugin needing to know where it came from. Those installs
     * are also the ones most likely to overwrite wp-config.php on deploy, which is the
     * failure this whole class is built around.
     *
     * @return string empty when this site has no key
     */
    public static function material()
    {
        $material = defined(self::CONSTANT) ? constant(self::CONSTANT) : '';

        $material = apply_filters('fluent_auth/secret_key_material', $material);

        return is_string($material) ? $material : '';
    }

    /**
     * @return bool whether a key is readable right now
     */
    public static function hasKey()
    {
        return self::material() !== '';
    }

    /**
     * A 32 byte key from whatever the user pasted.
     *
     * Derived rather than used directly so that any length, any character set and any
     * amount of copied whitespace produces a usable key - a constant that is four
     * characters long is a weak key, but it is not a broken one, and nobody should meet
     * an error message for pasting something short.
     *
     * @param string $material
     * @return string 32 raw bytes, or empty
     */
    public static function derive($material)
    {
        if (!is_string($material) || $material === '') {
            return '';
        }

        return hash_hmac('sha256', 'fluent-auth/totp-secret/v1', $material, true);
    }

    /**
     * Names a key without revealing it, so a ciphertext can say which one it belongs to.
     *
     * @param string $key raw bytes
     * @return string
     */
    public static function fingerprint($key)
    {
        if (!is_string($key) || $key === '') {
            return '';
        }

        return substr(hash_hmac('sha256', 'fluent-auth/key-id/v1', $key), 0, 16);
    }

    /**
     * The key in force.
     *
     * @return string 32 raw bytes, or empty when there is no usable key
     */
    public static function current()
    {
        return self::isEnabled() ? self::derive(self::material()) : '';
    }

    /**
     * @return array empty when encryption has never been switched on
     */
    public static function state()
    {
        $state = get_option(self::STATE_OPTION);

        if (!is_array($state) || empty($state['canary'])) {
            return [];
        }

        return $state;
    }

    /**
     * @return bool whether encryption is meant to be in force
     */
    public static function isEnabled()
    {
        return (bool)self::state();
    }

    /**
     * What is wrong, precisely enough to say what to do about it.
     *
     * The two failing answers are not interchangeable, and both are recoverable. A missing
     * constant is usually a deploy that overwrote wp-config.php, and is fixed by putting
     * the same line back. A changed one means the old value may still be in somebody's
     * password manager, and pasting it re-encrypts everything. Reporting both as
     * "decryption failed" would hide the fact that either can be undone.
     *
     * @return string one of the STATE_ constants
     */
    public static function diagnose()
    {
        $state = self::state();

        if (!$state) {
            return self::STATE_OFF;
        }

        $key = self::derive(self::material());

        if ($key !== '' && SecretCipher::reveal($state['canary'], $key) === self::CANARY_PLAINTEXT) {
            return self::STATE_OK;
        }

        return self::hasKey() ? self::STATE_KEY_CHANGED : self::STATE_CONSTANT_MISSING;
    }

    /**
     * @return bool whether stored secrets can be read right now
     */
    public static function isHealthy()
    {
        $state = self::diagnose();

        return $state === self::STATE_OK || $state === self::STATE_OFF;
    }

    /**
     * Records the key encryption is now under, by storing a canary rather than the key.
     *
     * @return bool
     */
    public static function adopt()
    {
        $key = self::derive(self::material());

        if ($key === '') {
            return false;
        }

        $canary = SecretCipher::protect(self::CANARY_PLAINTEXT, $key);

        if ($canary === '') {
            return false;
        }

        return update_option(self::STATE_OPTION, [
            'key_id'     => self::fingerprint($key),
            'canary'     => $canary,
            'created_at' => current_time('mysql')
        ], false);
    }

    /**
     * @return void
     */
    public static function forget()
    {
        delete_option(self::STATE_OPTION);
    }

    /**
     * A value worth pasting into wp-config.php.
     *
     * @return string empty when the server has no secure randomness
     */
    public static function generateValue()
    {
        try {
            return bin2hex(random_bytes(32));
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * The line to add, ready to be copied.
     *
     * @param string $value
     * @return string
     */
    public static function configLine($value)
    {
        return "define( '" . self::CONSTANT . "', '" . $value . "' );";
    }
}
