<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

use FluentAuth\App\Helpers\Arr;

/**
 * The checks that registration and authentication both owe.
 *
 * Four of the steps in sections 7.1 and 7.2 are the same words in both lists, and they
 * are the ones that decide whether the thing in front of us proves anything. Kept
 * together so there is one copy to get right, and so a change to what this site
 * demands of an authenticator cannot be made to one ceremony and forgotten in the
 * other.
 */
class Ceremony
{
    /**
     * How strongly the user has to prove they are there.
     *
     * "required" means the authenticator must have checked a fingerprint, a face or a
     * PIN, and it is the default because it is what makes a passkey worth having: the
     * device is something the user holds, the gesture is something they are, and
     * together they are two factors in one tap. Touch ID, Windows Hello and every
     * password manager that stores passkeys satisfy it.
     *
     * A site running bare security keys with no PIN configured can lower this to
     * "preferred" through the filter. It should know that it is then holding a factor
     * that anyone who picks the key up can use.
     *
     * @return string
     */
    public static function getUserVerificationRequirement()
    {
        $requirement = apply_filters('fluent_auth/webauthn_user_verification', 'required');

        return in_array($requirement, ['required', 'preferred', 'discouraged'], true)
            ? $requirement
            : 'required';
    }

    /**
     * @return bool
     */
    public static function isUserVerificationRequired()
    {
        return self::getUserVerificationRequirement() === 'required';
    }

    /**
     * Sections 7.1 steps 11-14 and 7.2 steps 15-18.
     *
     * @param $authData AuthenticatorData
     * @return void
     * @throws WebAuthnException
     */
    public static function verifyAuthenticatorData($authData)
    {
        /*
         * The authenticator hashes the relying party id it believes it is signing for.
         * This is the check that confines a credential to one domain, and it is what
         * makes a passkey phishing resistant where a typed code is not: a site that
         * merely looks like this one produces a different hash here, whatever the user
         * was persuaded to click.
         */
        if (!hash_equals(RelyingParty::getIdHash(), $authData->getRpIdHash())) {
            throw new WebAuthnException('Authenticator signed for a different relying party');
        }

        // Somebody was physically at the device. Without this the ceremony proves nothing.
        if (!$authData->isUserPresent()) {
            throw new WebAuthnException('Authenticator did not report user presence');
        }

        /*
         * If user verification was demanded it has to have happened. Skipping this while
         * the setting says "required" would leave the site holding possession only while
         * telling the user their fingerprint is what stands behind the account.
         */
        if (self::isUserVerificationRequired() && !$authData->isUserVerified()) {
            throw new WebAuthnException('Authenticator did not verify the user');
        }

        /*
         * A credential that says it is currently backed up while also saying it can
         * never be backed up is describing something that cannot exist, which means the
         * flags were not written by an authenticator following the rules.
         */
        if ($authData->hasFlag(AuthenticatorData::FLAG_BACKED_UP)
            && !$authData->hasFlag(AuthenticatorData::FLAG_BACKUP_ELIGIBLE)) {
            throw new WebAuthnException('Authenticator reported an impossible backup state');
        }
    }

    /**
     * Pulls one base64url field out of the browser's reply.
     *
     * @param $response array
     * @param $field string
     * @return string
     * @throws WebAuthnException
     */
    public static function decodeField($response, $field)
    {
        $value = Arr::get((array)$response, $field);

        if (!is_string($value) || $value === '') {
            throw new WebAuthnException('Response is missing ' . $field);
        }

        $decoded = Base64Url::decode($value);

        if ($decoded === false || $decoded === '') {
            throw new WebAuthnException('Response field ' . $field . ' is not valid base64url');
        }

        return $decoded;
    }

    /**
     * A fresh challenge.
     *
     * Thirty-two bytes from the cryptographically secure source. The challenge is the
     * only thing standing between a replayed assertion and a successful login, so it
     * must never come from mt_rand or from anything derived from the clock.
     *
     * @return string
     * @throws WebAuthnException
     */
    public static function createChallenge()
    {
        try {
            return random_bytes(32);
        } catch (\Exception $e) {
            throw new WebAuthnException('No source of randomness is available for a challenge');
        }
    }
}
