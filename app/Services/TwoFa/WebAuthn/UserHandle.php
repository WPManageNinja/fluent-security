<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * The opaque identifier an authenticator stores alongside a credential.
 *
 * It is written into the authenticator at registration and handed back at every login,
 * including - for a discoverable credential - before the site knows who is signing in.
 * Anything readable in it is therefore readable by any site or device that can ask the
 * authenticator to list what it holds, which is why it must not be the user id, the
 * login name or the email address.
 *
 * Sixty-four random bytes, generated once and kept in user meta. Stable for the life of
 * the account: regenerating it would orphan every passkey already registered, since the
 * authenticator would keep handing back the old one.
 */
class UserHandle
{
    const META_KEY = '_fls_webauthn_user_handle';

    /**
     * @param $user \WP_User|int
     * @return string raw bytes
     * @throws WebAuthnException
     */
    public static function getOrCreate($user)
    {
        $userId = $user instanceof \WP_User ? (int)$user->ID : (int)$user;

        if (!$userId) {
            throw new WebAuthnException('Cannot build a user handle without a user');
        }

        $stored = get_user_meta($userId, self::META_KEY, true);

        if (is_string($stored) && $stored !== '') {
            $decoded = Base64Url::decode($stored);

            if ($decoded !== false && strlen($decoded) === 64) {
                return $decoded;
            }
        }

        try {
            $handle = random_bytes(64);
        } catch (\Exception $e) {
            throw new WebAuthnException('No source of randomness is available for a user handle');
        }

        update_user_meta($userId, self::META_KEY, Base64Url::encode($handle));

        return $handle;
    }

    /**
     * @param $user \WP_User|int
     * @return string raw bytes, empty when the user has never registered a passkey
     */
    public static function get($user)
    {
        $userId = $user instanceof \WP_User ? (int)$user->ID : (int)$user;

        if (!$userId) {
            return '';
        }

        $stored = get_user_meta($userId, self::META_KEY, true);

        if (!is_string($stored) || $stored === '') {
            return '';
        }

        $decoded = Base64Url::decode($stored);

        return $decoded === false ? '' : $decoded;
    }
}
