<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

use FluentAuth\App\Helpers\Arr;

/**
 * Signing in with a passkey - the checklist from WebAuthn section 7.2.
 *
 * As with registration, the step numbers are the specification's and every step is
 * either carried out or named and dismissed. The order matters: the cheap structural
 * checks come before the signature check, so a malformed reply costs a string compare
 * rather than an RSA verification.
 */
class Assertion
{
    /**
     * Builds what the browser needs to produce an assertion.
     *
     * @param $challenge string raw bytes
     * @param $credentials array rows from PasskeyStore
     * @return array
     */
    public static function getRequestOptions($challenge, $credentials)
    {
        $allow = [];

        foreach ($credentials as $credential) {
            $entry = [
                'type' => 'public-key',
                'id'   => $credential->credential_id
            ];

            /*
             * Naming the transports a credential was registered with is what lets a
             * browser go straight to the right prompt instead of offering every option
             * it can think of - the difference between Touch ID appearing immediately
             * and the user being asked to pick from a menu that includes a USB key they
             * do not own.
             */
            if (is_array($credential->transports) && $credential->transports) {
                $entry['transports'] = array_values(array_filter($credential->transports, 'is_string'));
            }

            $allow[] = $entry;
        }

        return apply_filters('fluent_auth/webauthn_request_options', [
            'challenge'        => Base64Url::encode($challenge),
            'rpId'             => RelyingParty::getId(),
            'allowCredentials' => $allow,
            'timeout'          => 120000,
            'userVerification' => Ceremony::getUserVerificationRequirement()
        ], $credentials);
    }

    /**
     * Checks an assertion against the credential it claims to come from.
     *
     * @param $response array clientDataJSON, authenticatorData, signature, rawId, userHandle
     * @param $credential object the stored row this assertion names
     * @param $challenge string raw bytes, as issued
     * @param $user \WP_User the account the login is for
     * @return int the new signature counter, to be written back
     * @throws WebAuthnException
     */
    public static function verify($response, $credential, $challenge, $user)
    {
        $clientDataJson = Ceremony::decodeField($response, 'clientDataJSON');
        $authenticatorData = Ceremony::decodeField($response, 'authenticatorData');
        $signature = Ceremony::decodeField($response, 'signature');
        $rawId = Ceremony::decodeField($response, 'rawId');

        /*
         * Steps 1-3: the credential answering must be one that was asked for. The caller
         * selected the row by this id, so the comparison is against what it found - this
         * catches a reply that names one credential in its id field and another in the
         * body, which would otherwise be verified against the wrong public key.
         */
        if (!hash_equals((string)$credential->credential_id, Base64Url::encode($rawId))) {
            throw new WebAuthnException('Assertion does not match the credential it names');
        }

        // Steps 4-5: that credential belongs to the account being signed into.
        if ((int)$credential->user_id !== (int)$user->ID) {
            throw new WebAuthnException('Credential belongs to a different account');
        }

        /*
         * Step 6: where the authenticator volunteered a user handle it has to be this
         * user's. A discoverable credential always sends one; a non-discoverable one
         * often sends nothing, which is permitted and not an error.
         */
        $userHandle = Arr::get((array)$response, 'userHandle');

        if (is_string($userHandle) && $userHandle !== '') {
            $decodedHandle = Base64Url::decode($userHandle);
            $expectedHandle = UserHandle::get($user);

            if ($decodedHandle === false || $expectedHandle === '' || !hash_equals($expectedHandle, $decodedHandle)) {
                throw new WebAuthnException('Assertion carries a user handle for a different account');
            }
        }

        // Steps 7-10: read the client data.
        $clientData = new ClientData($clientDataJson);

        // Steps 11-13. Step 14 is token binding, which no current browser implements.
        $clientData->verify(
            ClientData::TYPE_GET,
            $challenge,
            RelyingParty::getAllowedOrigins()
        );

        $authData = new AuthenticatorData($authenticatorData);

        // Steps 15-18: relying party, presence, verification, backup flags.
        Ceremony::verifyAuthenticatorData($authData);

        /*
         * Steps 20-21: the authenticator signed its own data followed by the hash of
         * the client data. Concatenated in that order and in no other - the hash is of
         * the exact bytes that arrived, not of a re-encoding of the parsed JSON, since
         * any difference in key order or escaping would produce a different hash and
         * fail a signature that was perfectly good.
         */
        $signedData = $authData->getRaw() . $clientData->getHash();

        $key = CoseKey::fromStored($credential->public_key, (int)$credential->algorithm);

        if (!$key->verify($signedData, $signature)) {
            throw new WebAuthnException('Passkey signature did not verify');
        }

        // Step 22: the counter, where the authenticator keeps one.
        self::verifySignCount($authData->getSignCount(), (int)$credential->sign_count, $credential);

        return $authData->getSignCount();
    }

    /**
     * A counter that goes backwards means two authenticators are answering for one
     * credential, which is what a cloned device looks like from here.
     *
     * Only meaningful where the authenticator keeps a counter at all. Synced passkeys -
     * iCloud Keychain, a password manager - deliberately report zero forever, because
     * the same credential genuinely does live on several devices at once. Treating that
     * as a clone would lock out most of the people this feature is for, so a zero on
     * either side means the check does not apply.
     *
     * @param $presented int
     * @param $stored int
     * @param $credential object
     * @return void
     * @throws WebAuthnException
     */
    private static function verifySignCount($presented, $stored, $credential)
    {
        if ($presented === 0 || $stored === 0) {
            return;
        }

        if ($presented > $stored) {
            return;
        }

        do_action('fluent_auth/webauthn_sign_count_reused', $credential, $presented, $stored);

        throw new WebAuthnException('Passkey signature counter did not advance');
    }
}
