<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * Moving stored secrets between keys, or out from under one altogether.
 *
 * Three passes over the same handful of rows. A site has one authenticator row per
 * enrolled user and one more per abandoned setup, so even a large install is counted in
 * hundreds - which is why this is a straightforward loop rather than a batched background
 * job with state to resume. The whole thing finishes inside the request that asked for it.
 *
 * Every pass writes with $wpdb rather than through FactorStore::update(), and that is not
 * incidental: update() encrypts what it is given, so handing it an already-encrypted value
 * would encrypt it twice and handing it a plaintext one during decryptAll() would put it
 * straight back. These are the one caller that has to reach past the seam.
 */
class SecretMigration
{
    /**
     * Encrypts everything still in the clear, under the key now in force.
     *
     * Safe to run at any time and safe to run twice - a row already carrying the prefix is
     * skipped. This is the pass that runs when encryption is switched on, and the reason
     * turning it on is a single click rather than a migration somebody has to schedule.
     *
     * @return int how many rows were encrypted
     */
    public static function encryptAll()
    {
        $key = SecretKey::current();

        if ($key === '' || !FactorStore::hasTable()) {
            return 0;
        }

        $changed = 0;

        foreach (self::rows() as $row) {
            if (SecretCipher::isProtected($row->secret) || (string)$row->secret === '') {
                continue;
            }

            $protected = SecretCipher::protect((string)$row->secret, $key);

            if ($protected === '') {
                continue;
            }

            if (self::write($row->id, $protected)) {
                $changed++;
            }
        }

        return $changed;
    }

    /**
     * Puts everything back in the clear, for turning encryption off.
     *
     * Requires the key, because the rows cannot be read without it. That is why removing
     * the line from wp-config.php is not a way to turn encryption off - it is a way to
     * lose the secrets, and the screen says so.
     *
     * @return int|\WP_Error how many rows were decrypted
     */
    public static function decryptAll()
    {
        $key = SecretKey::current();

        if ($key === '') {
            return new \WP_Error(
                'no_key',
                __('The encryption key is not readable, so the stored secrets cannot be decrypted. Restore the key first.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (!FactorStore::hasTable()) {
            return 0;
        }

        $changed = 0;

        foreach (self::rows() as $row) {
            if (!SecretCipher::isProtected($row->secret)) {
                continue;
            }

            $revealed = SecretCipher::reveal((string)$row->secret, $key);

            /*
             * Left alone rather than emptied. A row this pass cannot read is a row encrypted
             * under some earlier key, and the user it belongs to will be asked to re-pair;
             * blanking it here would take away the one piece of evidence that says why.
             */
            if ($revealed === false || $revealed === '') {
                continue;
            }

            if (self::write($row->id, $revealed)) {
                $changed++;
            }
        }

        return $changed;
    }

    /**
     * Re-encrypts everything from a key the site no longer has to the one it has now.
     *
     * The old value is checked against the stored canary before a single row is touched,
     * so a wrong paste is an error message rather than a table half-converted under a key
     * nobody has. That check is the reason the canary is worth storing at all.
     *
     * @param string $oldValue the previous key material, as it was in wp-config.php
     * @return array|\WP_Error
     */
    public static function rekey($oldValue)
    {
        $state = SecretKey::state();

        if (!$state) {
            return new \WP_Error(
                'not_encrypted',
                __('This site is not using encrypted authenticator secrets, so there is nothing to re-key.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $oldKey = SecretKey::derive(trim((string)$oldValue));

        if ($oldKey === '') {
            return new \WP_Error(
                'no_old_key',
                __('Please paste the previous encryption key.', 'fluent-security'),
                ['status' => 422]
            );
        }

        if (SecretCipher::reveal($state['canary'], $oldKey) !== SecretKey::CANARY_PLAINTEXT) {
            return new \WP_Error(
                'wrong_old_key',
                __('That is not the key these secrets were encrypted with, so nothing has been changed. Check the value you pasted.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $newKey = SecretKey::derive(SecretKey::material());

        if ($newKey === '') {
            return new \WP_Error(
                'no_new_key',
                __('There is no key to re-encrypt with. Add the key to your wp-config.php first.', 'fluent-security'),
                ['status' => 422]
            );
        }

        $changed = 0;
        $failed = 0;

        foreach (self::rows() as $row) {
            if (!SecretCipher::isProtected($row->secret)) {
                continue;
            }

            $revealed = SecretCipher::reveal((string)$row->secret, $oldKey);

            if ($revealed === false || $revealed === '') {
                /*
                 * Not readable with the old key either. Counted and reported rather than
                 * swallowed: it means there was a key before the old one, and the person
                 * doing this needs to know some rows are still beyond reach.
                 */
                $failed++;

                continue;
            }

            $protected = SecretCipher::protect($revealed, $newKey);

            if ($protected === '' || !self::write($row->id, $protected)) {
                $failed++;

                continue;
            }

            $changed++;
        }

        /*
         * The canary goes last. Until it is rewritten the site still describes itself as
         * keyed to the old value, which is the honest state to be interrupted in - a
         * canary claiming the new key over rows still holding the old one would report a
         * healthy site that cannot read itself.
         */
        SecretKey::adopt();

        return [
            'changed' => $changed,
            'failed'  => $failed
        ];
    }

    /**
     * How many stored secrets cannot be read with the key in force.
     *
     * What the warning on the screen counts, and the number that says how many people will
     * be asked to pair their phone again.
     *
     * @return int
     */
    public static function unreadableCount()
    {
        if (!FactorStore::hasTable()) {
            return 0;
        }

        $key = SecretKey::current();
        $count = 0;

        foreach (self::rows() as $row) {
            if (!SecretCipher::isProtected($row->secret)) {
                continue;
            }

            if ($key === '' || SecretCipher::reveal((string)$row->secret, $key) === false) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * How many stored secrets are sitting in the clear.
     *
     * @return int
     */
    public static function plaintextCount()
    {
        if (!FactorStore::hasTable()) {
            return 0;
        }

        $count = 0;

        foreach (self::rows() as $row) {
            if ((string)$row->secret !== '' && !SecretCipher::isProtected($row->secret)) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Every authenticator row, as stored.
     *
     * Read straight from the table rather than through FactorStore, which decrypts on the
     * way out - these passes are all about the stored form, so the one thing they must not
     * have is a helpful layer that hides it.
     *
     * @return array
     */
    protected static function rows()
    {
        return flsDb()->table('fls_auth_factors')
            ->select(['id', 'secret'])
            ->where('type', FactorStore::TYPE_TOTP)
            ->get();
    }

    /**
     * @param $id int
     * @param $secret string exactly as it should be stored
     * @return bool
     */
    protected static function write($id, $secret)
    {
        global $wpdb;

        $written = $wpdb->update(
            FactorStore::table(),
            ['secret' => $secret, 'updated_at' => current_time('mysql')],
            ['id' => (int)$id]
        );

        return $written !== false;
    }
}
