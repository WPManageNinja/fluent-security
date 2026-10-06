<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;

/**
 * The codes a user falls back on when every device is gone.
 *
 * They belong to the account rather than to any one method. That is a change from where
 * they started - nested inside the authenticator app's own record - and it is the whole
 * point of the move: a passkey has no code of its own to type, so while recovery lived
 * inside the authenticator app, a user with only passkeys had nothing behind them and
 * could not safely be challenged with one at all.
 *
 * One row per code rather than a list in a single record, which makes spending one an
 * update the database arbitrates instead of a read, a rewrite, and a hope that no other
 * login was doing the same thing. That is not a theoretical race: recovery codes are
 * used precisely when somebody is locked out and trying repeatedly.
 *
 * A spent code is kept with its status changed rather than deleted, so "you have three
 * left" and "this one has already been used" are different answers.
 */
class RecoveryCodes
{
    const CODE_COUNT = 10;

    const CODE_LENGTH = 10;

    /**
     * No I, O, 0 or 1: these get copied down by hand under stress, usually because the
     * phone that held the other factor is gone.
     */
    const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    /**
     * Issues a fresh set, retiring whatever is left of the old one.
     *
     * Only the hashes are kept, so this is the one moment the codes can be shown.
     *
     * @param $user \WP_User|int
     * @return array the plaintext codes, to display once
     */
    public static function generate($user)
    {
        $userId = self::resolveUserId($user);

        if (!$userId || !FactorStore::ensureTable()) {
            return [];
        }

        /*
         * The old set goes before the new one arrives. Leaving spent or unspent codes
         * from a previous secret behind would mean a re-enrollment did not actually
         * replace anything, and the codes somebody printed a year ago still open the
         * account.
         */
        self::clear($userId);

        $codes = [];

        for ($i = 0; $i < self::CODE_COUNT; $i++) {
            $code = self::generateCode();

            if ($code === '') {
                self::clear($userId);

                return [];
            }

            $stored = FactorStore::insert([
                'user_id'    => $userId,
                'type'       => FactorStore::TYPE_RECOVERY,
                'status'     => FactorStore::STATUS_ACTIVE,
                'identifier' => self::hash($userId, $code)
            ]);

            if (is_wp_error($stored)) {
                self::clear($userId);

                return [];
            }

            $codes[] = $code;
        }

        do_action('fluent_auth/recovery_codes_generated', $userId, count($codes));

        return $codes;
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    public static function countRemaining($user)
    {
        return FactorStore::countForUser($user, FactorStore::TYPE_RECOVERY, FactorStore::STATUS_ACTIVE);
    }

    /**
     * @param $user \WP_User|int
     * @return bool
     */
    public static function hasAny($user)
    {
        return self::countRemaining($user) > 0;
    }

    /**
     * Spends a code if it matches an unused one.
     *
     * @param $user \WP_User|int
     * @param $code string already normalised to the alphabet
     * @return bool
     */
    public static function consume($user, $code)
    {
        $userId = self::resolveUserId($user);

        if (!$userId || !is_string($code) || $code === '') {
            return false;
        }

        $row = FactorStore::findByIdentifier(FactorStore::TYPE_RECOVERY, self::hash($userId, $code));

        /*
         * Codes issued before recovery moved into its own table were hashed without the
         * account in them. Their rows carry a marker and are matched on the old hash, so
         * a sheet somebody printed and filed still works. The owner check below is what
         * makes that safe: an unbound hash is the same for every account, so the row
         * must be confirmed to belong to this one - which for a bound hash is already
         * implied and here is load bearing.
         */
        if (!$row) {
            $row = FactorStore::findByIdentifier(FactorStore::TYPE_RECOVERY, self::legacyHash($code));

            if ($row && !Arr::get(FactorStore::readMeta($row), 'legacy_hash')) {
                $row = null;
            }
        }

        if (!$row || (int)$row->user_id !== $userId) {
            return false;
        }

        /*
         * The status is part of the update's condition, so of two requests presenting
         * the same code together only one is told it worked. Checking the status first
         * and updating afterwards would let both through.
         */
        if (!FactorStore::transition($row->id, FactorStore::STATUS_ACTIVE, FactorStore::STATUS_USED)) {
            return false;
        }

        do_action('fluent_auth/recovery_code_used', $userId, self::countRemaining($userId));

        return true;
    }

    /**
     * @param $user \WP_User|int
     * @return void
     */
    public static function clear($user)
    {
        FactorStore::deleteForUser($user, FactorStore::TYPE_RECOVERY);
    }

    /**
     * Whether something typed into a login form looks like a recovery code rather than
     * a six digit one from an authenticator app.
     *
     * Length is what tells them apart, which is why the two are different lengths.
     *
     * @param $normalised string
     * @return bool
     */
    public static function looksLikeCode($normalised)
    {
        return is_string($normalised) && strlen($normalised) === self::CODE_LENGTH;
    }

    /**
     * @return string empty when no secure randomness is available
     */
    private static function generateCode()
    {
        $code = '';

        for ($c = 0; $c < self::CODE_LENGTH; $c++) {
            try {
                $index = random_int(0, strlen(self::ALPHABET) - 1);
            } catch (\Exception $e) {
                return '';
            }

            $code .= self::ALPHABET[$index];
        }

        return $code;
    }

    /**
     * Bound to the user as well as to the site.
     *
     * Without the user in the hash, the same code issued to two accounts would land on
     * the same row - the identifier is unique per type - and one of them would silently
     * fail to store. It also means a code lifted from one account's printout cannot be
     * presented against another.
     *
     * Hashed rather than encrypted, and with a salt rather than bcrypt: each code
     * already carries fifty bits of entropy, so there is nothing to brute force, and a
     * login has to be able to check one without stalling.
     *
     * @param $userId int
     * @param $code string
     * @return string
     */
    private static function hash($userId, $code)
    {
        return hash_hmac('sha256', $userId . '|' . $code, wp_salt('secure_auth'));
    }

    /**
     * How codes were hashed before they had a table of their own: site salt only, with
     * nothing tying the result to an account.
     *
     * Kept solely so migrated codes still work. Nothing issues these any more.
     *
     * @param $code string
     * @return string
     */
    private static function legacyHash($code)
    {
        return hash_hmac('sha256', $code, wp_salt('secure_auth'));
    }

    /**
     * @param $user \WP_User|int
     * @return int
     */
    private static function resolveUserId($user)
    {
        if ($user instanceof \WP_User) {
            return (int)$user->ID;
        }

        return is_numeric($user) ? (int)$user : 0;
    }
}
