<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

use FluentAuth\App\Services\TwoFa\FactorStore;

/**
 * Passkeys, as rows in the shared second factor table.
 *
 * Everything above this layer speaks WebAuthn - credential ids, public keys, signature
 * counters - and everything below it speaks storage. The translation happens here and
 * nowhere else, so Assertion and Registration never learn that a public key is kept in
 * a column called `secret` alongside an authenticator app's shared secret. Rename a
 * column and this file changes; nothing else does.
 */
class PasskeyStore
{
    /**
     * @return bool
     */
    public static function ensureTable()
    {
        return FactorStore::ensureTable();
    }

    /**
     * @param $user \WP_User|int
     * @return array
     */
    public static function getForUser($user)
    {
        return array_map(
            [self::class, 'hydrate'],
            FactorStore::forUser($user, FactorStore::TYPE_PASSKEY)
        );
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    public static function countForUser($user)
    {
        return FactorStore::countForUser($user, FactorStore::TYPE_PASSKEY);
    }

    /**
     * @param $credentialId string base64url
     * @return object|null
     */
    public static function findByCredentialId($credentialId)
    {
        $row = FactorStore::findByIdentifier(FactorStore::TYPE_PASSKEY, $credentialId);

        return $row ? self::hydrate($row) : null;
    }

    /**
     * Stores a newly registered credential.
     *
     * @param $user \WP_User|int
     * @param $verified array as returned by Registration::verify()
     * @param $label string what the user calls this device
     * @param $transports array
     * @return int|\WP_Error the new row id
     */
    public static function add($user, $verified, $label = '', $transports = [])
    {
        $userId = $user instanceof \WP_User ? (int)$user->ID : (int)$user;

        if (!$userId) {
            return new \WP_Error('invalid_user', __('Unknown user', 'fluent-security'));
        }

        $credentialId = isset($verified['credential_id']) ? (string)$verified['credential_id'] : '';

        /*
         * Refused here rather than truncated, because the identifier is indexed to 180
         * characters. A credential longer than that would be stored under a prefix that
         * a second credential could also match, and two passkeys answering to one row is
         * worse than one authenticator that cannot be registered.
         */
        if ($credentialId === '' || strlen($credentialId) > 180) {
            return new \WP_Error(
                'invalid_credential',
                __('This authenticator returned an unusable credential', 'fluent-security')
            );
        }

        /*
         * Section 7.1 step 20: a credential id already on file is refused, whoever it
         * belongs to. Asked here so the answer names what went wrong; the unique index
         * underneath is what makes it true when two registrations race.
         */
        if (self::findByCredentialId($credentialId)) {
            return new \WP_Error('already_registered', __('That passkey is already registered', 'fluent-security'));
        }

        $id = FactorStore::insert([
            'user_id'    => $userId,
            'type'       => FactorStore::TYPE_PASSKEY,
            'status'     => FactorStore::STATUS_ACTIVE,
            // Unique per type, which is what enforces section 7.1 step 20 in the database.
            'identifier' => $credentialId,
            'secret'     => (string)$verified['public_key'],
            'counter'    => (int)$verified['sign_count'],
            'label'      => self::sanitiseLabel($label),
            'meta'       => [
                'algorithm'       => (int)$verified['algorithm'],
                'transports'      => array_values(array_filter((array)$transports, 'is_string')),
                'aaguid'          => isset($verified['aaguid']) ? substr((string)$verified['aaguid'], 0, 32) : '',
                'backup_eligible' => !empty($verified['backup_eligible'])
            ]
        ]);

        if (is_wp_error($id)) {
            return $id;
        }

        do_action('fluent_auth/passkey_registered', $userId, $id);

        return $id;
    }

    /**
     * @param $credential object as returned by hydrate()
     * @param $signCount int
     * @return void
     */
    public static function touch($credential, $signCount)
    {
        FactorStore::touch((int)$credential->id, (int)$signCount);
    }

    /**
     * @param $id int
     * @param $user \WP_User|int
     * @return bool
     */
    public static function delete($id, $user)
    {
        $userId = $user instanceof \WP_User ? (int)$user->ID : (int)$user;

        if (!FactorStore::delete($id, $userId)) {
            return false;
        }

        do_action('fluent_auth/passkey_removed', $userId, (int)$id);

        return true;
    }

    /**
     * @param $id int
     * @param $user \WP_User|int
     * @param $label string
     * @return bool
     */
    public static function rename($id, $user, $label)
    {
        $userId = $user instanceof \WP_User ? (int)$user->ID : (int)$user;

        if (!FactorStore::findOwned($id, $userId)) {
            return false;
        }

        FactorStore::update($id, ['label' => self::sanitiseLabel($label)]);

        return true;
    }

    /**
     * Removes every passkey belonging to a user.
     *
     * The user handle goes with them. Leaving it would mean a later re-registration
     * reused a handle that authenticators still hold against credentials this site has
     * forgotten, so the stale entries in somebody's password manager would keep looking
     * live in their list.
     *
     * @param $user \WP_User|int
     * @return void
     */
    public static function deleteAllForUser($user)
    {
        $userId = $user instanceof \WP_User ? (int)$user->ID : (int)$user;

        if (!$userId) {
            return;
        }

        FactorStore::deleteForUser($userId, FactorStore::TYPE_PASSKEY);

        delete_user_meta($userId, UserHandle::META_KEY);

        do_action('fluent_auth/passkeys_cleared', $userId);
    }

    /**
     * A stored row in the vocabulary the WebAuthn code uses.
     *
     * @param $row object
     * @return object
     */
    private static function hydrate($row)
    {
        $meta = FactorStore::readMeta($row);

        return (object)[
            'id'              => (int)$row->id,
            'user_id'         => (int)$row->user_id,
            'credential_id'   => (string)$row->identifier,
            'public_key'      => (string)$row->secret,
            'sign_count'      => (int)$row->counter,
            'algorithm'       => isset($meta['algorithm']) ? (int)$meta['algorithm'] : 0,
            'transports'      => isset($meta['transports']) && is_array($meta['transports']) ? $meta['transports'] : [],
            'aaguid'          => isset($meta['aaguid']) ? (string)$meta['aaguid'] : '',
            'backup_eligible' => !empty($meta['backup_eligible']),
            'label'           => (string)$row->label,
            'last_used_at'    => $row->last_used_at,
            'created_at'      => $row->created_at
        ];
    }

    /**
     * @param $label string
     * @return string
     */
    private static function sanitiseLabel($label)
    {
        $label = trim(sanitize_text_field((string)$label));

        if ($label === '') {
            $label = __('Passkey', 'fluent-security');
        }

        // mb_substr so a multibyte name is cut on a character rather than mid-sequence.
        return function_exists('mb_substr') ? mb_substr($label, 0, 60) : substr($label, 0, 60);
    }
}
