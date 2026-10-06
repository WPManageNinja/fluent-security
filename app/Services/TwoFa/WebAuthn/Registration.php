<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * Registering a new passkey - the checklist from WebAuthn section 7.1.
 *
 * The step numbers in the comments are that section's, kept so this can be read side
 * by side with the specification and audited for something missing. Steps that do not
 * apply here are named and dismissed rather than left out, because a checklist with
 * silent gaps cannot be distinguished from one with accidental ones.
 *
 * Attestation is not verified, and that is deliberate rather than a shortcut. The
 * registration options ask for none, which makes the browser strip the attestation
 * statement before it ever arrives; what survives is the public key, which is all a
 * site needs unless it is an enterprise restricting which makes and models of
 * authenticator its staff may use. Verifying attestation would mean shipping and
 * maintaining a root certificate store to answer a question this plugin does not ask.
 */
class Registration
{
    /**
     * Builds what the browser needs to create a credential.
     *
     * @param $user \WP_User
     * @param $challenge string raw bytes
     * @param $excludeCredentialIds array base64url ids already registered to this user
     * @return array
     */
    public static function getCreationOptions($user, $challenge, $excludeCredentialIds = [])
    {
        $exclude = [];

        foreach ($excludeCredentialIds as $id) {
            $exclude[] = [
                'type' => 'public-key',
                'id'   => $id
            ];
        }

        $options = [
            'challenge' => Base64Url::encode($challenge),
            'rp'        => [
                'id'   => RelyingParty::getId(),
                'name' => RelyingParty::getName()
            ],
            'user'      => [
                /*
                 * An opaque per-user handle, not the numeric user id. The handle is
                 * stored on the authenticator and can be read back by anything that
                 * later asks it for a credential, so it must not carry anything about
                 * the account - and an incrementing integer carries how many accounts
                 * the site has and roughly when this one was made.
                 */
                'id'          => Base64Url::encode(UserHandle::getOrCreate($user)),
                'name'        => $user->user_login,
                'displayName' => $user->display_name ? $user->display_name : $user->user_login
            ],
            /*
             * Order is a preference, and ES256 first is the one every authenticator
             * can do. RS256 follows for TPM backed Windows Hello credentials. Nothing
             * else is offered, so nothing else can be registered.
             */
            'pubKeyCredParams'       => [
                ['type' => 'public-key', 'alg' => CoseKey::ES256],
                ['type' => 'public-key', 'alg' => CoseKey::RS256]
            ],
            'timeout'                => 120000,
            // See the class comment: asking for none is what keeps attestation out of the reply.
            'attestation'            => 'none',
            'excludeCredentials'     => $exclude,
            'authenticatorSelection' => [
                'residentKey'      => 'preferred',
                'userVerification' => Ceremony::getUserVerificationRequirement()
            ]
        ];

        return apply_filters('fluent_auth/webauthn_creation_options', $options, $user);
    }

    /**
     * Checks a newly created credential and returns what should be stored for it.
     *
     * @param $response array the browser's reply: clientDataJSON, attestationObject, rawId
     * @param $challenge string raw bytes, as issued
     * @return array credential_id, public_key, algorithm, sign_count, aaguid, backup_eligible
     * @throws WebAuthnException
     */
    public static function verify($response, $challenge)
    {
        $clientDataJson = Ceremony::decodeField($response, 'clientDataJSON');
        $attestationObject = Ceremony::decodeField($response, 'attestationObject');
        $rawId = Ceremony::decodeField($response, 'rawId');

        // Steps 1-4: read the client data. Anything unparseable fails here.
        $clientData = new ClientData($clientDataJson);

        /*
         * Steps 5-7: the ceremony is a registration, the challenge is the one this site
         * issued, and the origin is this site. Step 8 concerns token binding, which no
         * current browser implements and which the specification permits ignoring.
         */
        $clientData->verify(
            ClientData::TYPE_CREATE,
            $challenge,
            RelyingParty::getAllowedOrigins()
        );

        // Step 10: unpack the attestation object.
        $attestation = Cbor::decode($attestationObject);

        if (!is_array($attestation) || !isset($attestation['authData']) || !is_string($attestation['authData'])) {
            throw new WebAuthnException('Attestation object has no authenticator data');
        }

        $authData = new AuthenticatorData($attestation['authData']);

        if (!$authData->hasFlag(AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA)) {
            throw new WebAuthnException('Registration carried no credential to attest');
        }

        // Steps 11-14: the relying party, the gestures, and the backup flags.
        Ceremony::verifyAuthenticatorData($authData);

        /*
         * Steps 16-18: verify the attestation statement. Skipped by design - see the
         * class comment. The format is read only so that a statement arriving where
         * none was asked for is noticed rather than silently ignored.
         */
        $format = isset($attestation['fmt']) ? $attestation['fmt'] : '';

        if ($format !== 'none') {
            do_action('fluent_auth/webauthn_unexpected_attestation', $format);
        }

        // Step 15: the key is one of the algorithms that was offered, or this throws.
        $key = CoseKey::fromCbor($authData->getCredentialPublicKey());

        /*
         * The id the browser reported and the id the authenticator signed have to be
         * the same one. They are two separate fields in the reply and only the second
         * is covered by the attestation, so trusting the first would mean storing a key
         * under an id its owner never agreed to.
         */
        if (!hash_equals($authData->getCredentialId(), $rawId)) {
            throw new WebAuthnException('Reported credential id does not match the attested one');
        }

        return [
            'credential_id'    => Base64Url::encode($authData->getCredentialId()),
            'public_key'       => $key->getPem(),
            'algorithm'        => $key->getAlgorithm(),
            'sign_count'       => $authData->getSignCount(),
            'aaguid'           => bin2hex($authData->getAaguid()),
            'backup_eligible'  => $authData->isBackupEligible() ? 1 : 0,
            'user_verified'    => $authData->isUserVerified() ? 1 : 0
        ];
    }
}
