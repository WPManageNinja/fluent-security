<?php

namespace FluentAuth\App\Http\Controllers;

use FluentAuth\App\Services\ConfigWriter;
use FluentAuth\App\Services\TwoFa\FactorStore;
use FluentAuth\App\Services\TwoFa\SecretKey;
use FluentAuth\App\Services\TwoFa\SecretMigration;

/**
 * Switching encryption of the authenticator secrets on, off, or onto a new key.
 *
 * The awkward part of this, and the reason it is four endpoints rather than a setting, is
 * that the key lives in wp-config.php - a file that is already loaded by the time any of
 * this runs. Nothing here can see a line that was added to it during this request, so
 * `enable` cannot both install a key and confirm it. Any later request is a fresh PHP
 * process and can, which is why the flow is deliberately two calls: propose, then verify.
 *
 * Adopting a key on the strength of having written it would be the one mistake that really
 * costs something. A file write that a deploy reverts ten minutes later, or a managed host
 * silently discards, would leave a table full of ciphertext and no key anywhere - so the
 * key is only ever adopted after a separate request has read it back from a wp-config.php
 * that PHP actually loaded.
 */
class TwoFaEncryptionController
{
    /**
     * How long a proposed key stays offered.
     *
     * Kept in a transient rather than an option so that a value nobody used does not
     * linger. It is not protecting anything while it sits here - the rows are still
     * plaintext - but the moment it becomes the real key it must not also be in the
     * database, so it is deleted as soon as the constant appears. See status().
     */
    const PROPOSAL_TTL = 1800;

    const PROPOSAL_KEY = '__fls_auth_secret_key_proposal';

    public static function getStatus(\WP_REST_Request $request)
    {
        return ['encryption' => self::status()];
    }

    /**
     * Everything the screen needs to describe the situation and offer the one next step.
     *
     * @return array
     */
    protected static function status()
    {
        $diagnosis = SecretKey::diagnose();
        $supported = SecretKey::isSupported();

        /*
         * The proposed key is dropped the instant the constant is readable. Leaving it in
         * the options table after that would put the live key in the database, which is
         * precisely the leak the constant exists to avoid.
         */
        if (SecretKey::hasKey()) {
            delete_transient(self::PROPOSAL_KEY);
        }

        $status = [
            'supported'     => $supported,
            'state'         => $diagnosis,
            'enabled'       => SecretKey::isEnabled(),
            'healthy'       => SecretKey::isHealthy(),
            'has_key'       => SecretKey::hasKey(),
            'constant_name' => SecretKey::CONSTANT,
            'enrolled'      => count(FactorStore::getEnrolledUserIds(FactorStore::TYPE_TOTP)),
            'counts'        => [
                'plaintext'  => SecretMigration::plaintextCount(),
                'unreadable' => SecretMigration::unreadableCount()
            ],
            'config'        => ConfigWriter::state()
        ];

        /*
         * A line to copy, but only while there is nothing to lose by showing one. Once
         * encryption is on, the value in wp-config.php is the live key and this endpoint
         * has no business handing it back out.
         */
        if ($supported && !SecretKey::hasKey() && !SecretKey::isEnabled()) {
            $status['proposed_line'] = SecretKey::configLine(self::proposedValue());
        }

        return $status;
    }

    /**
     * The value being offered, stable across a reload.
     *
     * Generated once and remembered for half an hour, because a fresh value on every page
     * load means the line somebody copied is not the line the next screen is talking about.
     *
     * @return string
     */
    protected static function proposedValue()
    {
        $value = get_transient(self::PROPOSAL_KEY);

        if (is_string($value) && $value !== '') {
            return $value;
        }

        $value = SecretKey::generateValue();

        if ($value === '') {
            return '';
        }

        set_transient(self::PROPOSAL_KEY, $value, self::PROPOSAL_TTL);

        return $value;
    }

    /**
     * Adds the generated line to wp-config.php, if this site allows it.
     *
     * Writes and stops. It deliberately does not go on to switch encryption on, because it
     * cannot: wp-config.php was loaded before this request began, so the constant it has
     * just written is not defined in this process and will not be until the next one. The
     * screen therefore calls enable() afterwards as a separate request, which reads the
     * constant back from a file PHP actually loaded before it commits a single row to it.
     *
     * Every failure here is ordinary rather than exceptional - a read-only file on managed
     * hosting is the common case - so each one carries the sentence the screen shows next
     * to the line for pasting.
     */
    public static function writeConfig(\WP_REST_Request $request)
    {
        if (!SecretKey::isSupported()) {
            return new \WP_Error(
                'not_supported',
                __('This server cannot encrypt: the OpenSSL functions this needs are not available.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (SecretKey::hasKey()) {
            return [
                'written'    => false,
                'encryption' => self::status(),
                'message'    => __('A key is already in place.', 'fluent-security')
            ];
        }

        $value = self::proposedValue();

        if ($value === '') {
            return new \WP_Error(
                'no_value',
                __('A key could not be generated on this server.', 'fluent-security'),
                ['status' => 500]
            );
        }

        $written = ConfigWriter::addConstant(SecretKey::CONSTANT, $value);

        if (is_wp_error($written)) {
            /*
             * Reported as a result rather than an error status. The screen has a perfectly
             * good next step to offer - the same line, to paste by hand - and rendering
             * this as a failed request would put a red notification over a panel that is
             * about to tell them what to do instead.
             */
            return [
                'written'    => false,
                'encryption' => self::status(),
                'message'    => $written->get_error_message()
            ];
        }

        return [
            'written'    => true,
            'encryption' => self::status(),
            'message'    => __('The key has been added to your wp-config.php.', 'fluent-security')
        ];
    }

    /**
     * Adopts the key that is in place and encrypts what is already stored.
     *
     * Deliberately takes no key material of its own. A key arriving in a request body
     * would be a key travelling through the web server's logs and the browser's history,
     * and it would be adopted without ever proving it is somewhere the site can read it
     * again next request.
     */
    public static function enable(\WP_REST_Request $request)
    {
        if (!SecretKey::isSupported()) {
            return new \WP_Error(
                'not_supported',
                __('This server cannot encrypt: the OpenSSL functions this needs are not available.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (SecretKey::isEnabled()) {
            return [
                'encryption' => self::status(),
                'message'    => __('Authenticator secrets are already encrypted.', 'fluent-security')
            ];
        }

        if (!SecretKey::hasKey()) {
            /*
             * Nothing to key from. The most likely reason by far is that the line has been
             * copied but not yet saved, or saved to the wrong file - so the answer names
             * the file rather than reporting a generic failure.
             */
            return new \WP_Error(
                'key_not_readable',
                sprintf(
                    /* translators: %s: the wp-config.php constant name */
                    __('The %s line is not in place yet. Add it to your wp-config.php, save the file, and try again.', 'fluent-security'),
                    SecretKey::CONSTANT
                ),
                ['status' => 422]
            );
        }

        if (!SecretKey::adopt()) {
            return new \WP_Error(
                'not_adopted',
                __('The encryption key could not be recorded, so nothing has been changed.', 'fluent-security'),
                ['status' => 500]
            );
        }

        $encrypted = SecretMigration::encryptAll();

        // The live key must not also be sitting in the options table.
        delete_transient(self::PROPOSAL_KEY);

        return [
            'encryption' => self::status(),
            'message'    => $encrypted
                ? sprintf(
                    /* translators: %d: number of secrets encrypted */
                    _n(
                        'Encryption is on, and %d stored secret has been encrypted.',
                        'Encryption is on, and %d stored secrets have been encrypted.',
                        $encrypted,
                        'fluent-security'
                    ),
                    $encrypted
                )
                : __('Encryption is on. New authenticator apps will be stored encrypted.', 'fluent-security')
        ];
    }

    /**
     * Puts the secrets back in the clear.
     *
     * Needs the key, because they cannot be read without it - which is the whole reason
     * removing the line from wp-config.php is not a way to turn this off.
     */
    public static function disable(\WP_REST_Request $request)
    {
        if (!SecretKey::isEnabled()) {
            return [
                'encryption' => self::status(),
                'message'    => __('Authenticator secrets are not encrypted.', 'fluent-security')
            ];
        }

        $decrypted = SecretMigration::decryptAll();

        if (is_wp_error($decrypted)) {
            return $decrypted;
        }

        SecretKey::forget();

        return [
            'encryption' => self::status(),
            'message'    => __('Encryption is off and the stored secrets have been decrypted. You can remove the key from your wp-config.php now.', 'fluent-security')
        ];
    }

    /**
     * Moves everything from a key the site no longer has onto the one it has now.
     *
     * The recovery path for the two states that have one. The old value is checked against
     * the stored canary first, so a wrong paste changes nothing.
     */
    public static function rekey(\WP_REST_Request $request)
    {
        $oldKey = (string)$request->get_param('old_key');

        if (trim($oldKey) === '') {
            return new \WP_Error(
                'no_old_key',
                __('Please paste the previous encryption key.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $result = SecretMigration::rekey($oldKey);

        if (is_wp_error($result)) {
            return $result;
        }

        $message = sprintf(
            /* translators: %d: number of secrets re-encrypted */
            _n(
                '%d secret has been re-encrypted with the current key.',
                '%d secrets have been re-encrypted with the current key.',
                $result['changed'],
                'fluent-security'
            ),
            $result['changed']
        );

        if ($result['failed']) {
            $message .= ' ' . sprintf(
                /* translators: %d: number of secrets that could not be read */
                _n(
                    '%d could not be read even with that key, so its owner will be asked to pair a new app.',
                    '%d could not be read even with that key, so their owners will be asked to pair a new app.',
                    $result['failed'],
                    'fluent-security'
                ),
                $result['failed']
            );
        }

        return [
            'encryption' => self::status(),
            'message'    => $message
        ];
    }
}
