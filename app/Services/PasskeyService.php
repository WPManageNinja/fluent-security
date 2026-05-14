<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class PasskeyService
{
    const CHALLENGE_PREFIX = 'fls_passkey_challenge_';
    const CHALLENGE_TTL = 300;

    public static function isAvailable()
    {
        return apply_filters('fluent_auth/passkeys_enabled', Helper::getSetting('passkeys') === 'yes')
            && (is_ssl() || self::isLocalhost());
    }

    public static function getRegistrationOptions($user)
    {
        if (!$user || !$user->ID) {
            return new \WP_Error('invalid_user', __('You must be logged in to register a passkey.', 'fluent-security'), ['status' => 403]);
        }

        $challenge = self::randomBase64Url(32);
        $token = self::storeChallenge('register', $challenge, [
            'user_id' => (int)$user->ID
        ]);

        $excludeCredentials = [];
        foreach (PasskeyCredentialRepository::getByUserId($user->ID) as $credential) {
            $excludeCredentials[] = [
                'type' => 'public-key',
                'id'   => $credential->credential_id
            ];
        }

        $options = [
            'challengeToken' => $token,
            'publicKey'      => [
                'challenge'              => $challenge,
                'rp'                     => [
                    'name' => get_bloginfo('name'),
                    'id'   => self::getRpId()
                ],
                'user'                   => [
                    'id'          => self::base64UrlEncode((string)$user->ID),
                    'name'        => $user->user_login,
                    'displayName' => $user->display_name ?: $user->user_login
                ],
                'pubKeyCredParams'       => [
                    ['type' => 'public-key', 'alg' => -7],
                    ['type' => 'public-key', 'alg' => -257]
                ],
                'timeout'                => 60000,
                'attestation'            => 'none',
                'excludeCredentials'     => $excludeCredentials,
                'authenticatorSelection' => [
                    'residentKey'      => 'preferred',
                    'userVerification' => self::getUserVerification()
                ]
            ]
        ];

        return apply_filters('fluent_auth/passkey_registration_options', $options, $user);
    }

    public static function verifyRegistration($payload, $user)
    {
        if (!$user || !$user->ID) {
            return new \WP_Error('invalid_user', __('You must be logged in to register a passkey.', 'fluent-security'), ['status' => 403]);
        }

        $challengeData = self::consumeChallenge(Arr::get($payload, 'challengeToken'), 'register');
        if (is_wp_error($challengeData)) {
            return $challengeData;
        }

        if ((int)Arr::get($challengeData, 'user_id') !== (int)$user->ID) {
            return new \WP_Error('invalid_challenge', __('The passkey request could not be verified.', 'fluent-security'), ['status' => 422]);
        }

        $clientData = self::parseClientData(Arr::get($payload, 'response.clientDataJSON'), 'webauthn.create', Arr::get($challengeData, 'challenge'));
        if (is_wp_error($clientData)) {
            return $clientData;
        }

        $attestationObject = self::base64UrlDecode(Arr::get($payload, 'response.attestationObject'));
        if (!$attestationObject) {
            return new \WP_Error('invalid_attestation', __('Invalid passkey registration response.', 'fluent-security'), ['status' => 422]);
        }

        try {
            $attestation = self::decodeCbor($attestationObject);
            $authData = Arr::get($attestation, 'authData');
            $parsedAuthData = self::parseAuthenticatorData($authData, true);
        } catch (\Exception $e) {
            return new \WP_Error('invalid_attestation', __('Invalid passkey registration response.', 'fluent-security'), ['status' => 422]);
        }

        $rpHash = hash('sha256', self::getRpId(), true);
        if (!hash_equals($rpHash, $parsedAuthData['rp_id_hash'])) {
            return new \WP_Error('invalid_rp', __('This passkey is not valid for this site.', 'fluent-security'), ['status' => 422]);
        }

        if (!($parsedAuthData['flags'] & 0x01)) {
            return new \WP_Error('user_presence_required', __('Passkey verification requires user presence.', 'fluent-security'), ['status' => 422]);
        }

        if (self::getUserVerification() === 'required' && !($parsedAuthData['flags'] & 0x04)) {
            return new \WP_Error('user_verification_required', __('This passkey requires user verification.', 'fluent-security'), ['status' => 422]);
        }

        $credentialId = $parsedAuthData['credential_id'];
        if (PasskeyCredentialRepository::getByCredentialId(self::base64UrlEncode($credentialId))) {
            return new \WP_Error('credential_exists', __('This passkey is already registered.', 'fluent-security'), ['status' => 422]);
        }

        $publicKey = self::coseKeyToPem($parsedAuthData['credential_public_key']);
        if (is_wp_error($publicKey)) {
            return $publicKey;
        }

        PasskeyCredentialRepository::create([
            'user_id'          => $user->ID,
            'credential_id'    => self::base64UrlEncode($credentialId),
            'public_key'       => $publicKey['pem'],
            'cose_key'         => self::base64UrlEncode($parsedAuthData['credential_public_key_raw']),
            'alg'              => $publicKey['alg'],
            'sign_count'       => $parsedAuthData['sign_count'],
            'transports'       => Arr::get($payload, 'response.transports', []),
            'aaguid'           => bin2hex($parsedAuthData['aaguid']),
            'attestation_type' => Arr::get($attestation, 'fmt', 'none'),
            'name'             => self::getDefaultCredentialName($payload)
        ]);

        return true;
    }

    public static function getAuthenticationOptions($login = '')
    {
        $challenge = self::randomBase64Url(32);
        $user = null;
        $allowCredentials = [];

        if ($login) {
            $user = is_email($login) ? get_user_by('email', $login) : get_user_by('login', sanitize_user($login));
            if (!$user) {
                return new \WP_Error('invalid_user', __('No passkey is registered for this account.', 'fluent-security'), ['status' => 422]);
            }

            foreach (PasskeyCredentialRepository::getByUserId($user->ID) as $credential) {
                $allowCredentials[] = [
                    'type'       => 'public-key',
                    'id'         => $credential->credential_id,
                    'transports' => maybe_unserialize($credential->transports) ?: []
                ];
            }

            if (!$allowCredentials) {
                return new \WP_Error('no_passkeys', __('No passkey is registered for this account.', 'fluent-security'), ['status' => 422]);
            }
        }

        $token = self::storeChallenge('login', $challenge, [
            'user_id' => $user ? (int)$user->ID : 0,
            'login'   => $login
        ]);

        $options = [
            'challengeToken' => $token,
            'publicKey'      => [
                'challenge'        => $challenge,
                'rpId'             => self::getRpId(),
                'timeout'          => 60000,
                'userVerification' => self::getUserVerification()
            ]
        ];

        if ($allowCredentials) {
            $options['publicKey']['allowCredentials'] = $allowCredentials;
        }

        return apply_filters('fluent_auth/passkey_authentication_options', $options, $user);
    }

    public static function verifyAuthentication($payload)
    {
        $challengeData = self::consumeChallenge(Arr::get($payload, 'challengeToken'), 'login');
        if (is_wp_error($challengeData)) {
            return $challengeData;
        }

        $credentialId = self::base64UrlDecode(Arr::get($payload, 'id'));
        if (!$credentialId) {
            return new \WP_Error('invalid_credential', __('Invalid passkey response.', 'fluent-security'), ['status' => 422]);
        }

        $credential = PasskeyCredentialRepository::getByCredentialId(self::base64UrlEncode($credentialId));
        if (!$credential) {
            return new \WP_Error('invalid_credential', __('This passkey is not registered on this site.', 'fluent-security'), ['status' => 422]);
        }

        if (!empty($challengeData['user_id']) && (int)$credential->user_id !== (int)$challengeData['user_id']) {
            return new \WP_Error('invalid_credential', __('This passkey is not registered for this account.', 'fluent-security'), ['status' => 422]);
        }

        $clientDataJson = self::base64UrlDecode(Arr::get($payload, 'response.clientDataJSON'));
        $clientData = self::parseClientData(Arr::get($payload, 'response.clientDataJSON'), 'webauthn.get', Arr::get($challengeData, 'challenge'));
        if (is_wp_error($clientData)) {
            return $clientData;
        }

        $authenticatorData = self::base64UrlDecode(Arr::get($payload, 'response.authenticatorData'));
        $signature = self::base64UrlDecode(Arr::get($payload, 'response.signature'));
        if (!$authenticatorData || !$signature || !$clientDataJson) {
            return new \WP_Error('invalid_assertion', __('Invalid passkey login response.', 'fluent-security'), ['status' => 422]);
        }

        try {
            $parsedAuthData = self::parseAuthenticatorData($authenticatorData, false);
        } catch (\Exception $e) {
            return new \WP_Error('invalid_assertion', __('Invalid passkey login response.', 'fluent-security'), ['status' => 422]);
        }

        $rpHash = hash('sha256', self::getRpId(), true);
        if (!hash_equals($rpHash, $parsedAuthData['rp_id_hash'])) {
            return new \WP_Error('invalid_rp', __('This passkey is not valid for this site.', 'fluent-security'), ['status' => 422]);
        }

        if (!($parsedAuthData['flags'] & 0x01)) {
            return new \WP_Error('user_presence_required', __('Passkey verification requires user presence.', 'fluent-security'), ['status' => 422]);
        }

        if (self::getUserVerification() === 'required' && !($parsedAuthData['flags'] & 0x04)) {
            return new \WP_Error('user_verification_required', __('This passkey requires user verification.', 'fluent-security'), ['status' => 422]);
        }

        $verifyData = $authenticatorData . hash('sha256', $clientDataJson, true);
        $verified = openssl_verify($verifyData, $signature, $credential->public_key, self::opensslAlgorithm((int)$credential->alg));

        if ($verified !== 1) {
            return new \WP_Error('invalid_signature', __('Passkey signature verification failed.', 'fluent-security'), ['status' => 422]);
        }

        if ($parsedAuthData['sign_count'] && $credential->sign_count && $parsedAuthData['sign_count'] <= (int)$credential->sign_count) {
            return new \WP_Error('invalid_counter', __('Passkey verification failed. Please remove and register this passkey again.', 'fluent-security'), ['status' => 422]);
        }

        PasskeyCredentialRepository::updateUsed($credential->id, $parsedAuthData['sign_count']);

        $user = get_user_by('ID', $credential->user_id);
        if (!$user) {
            return new \WP_Error('invalid_user', __('User not found.', 'fluent-security'), ['status' => 422]);
        }

        return $user;
    }

    public static function getRpId()
    {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $host = strtolower($host ?: parse_url(site_url(), PHP_URL_HOST));
        $host = preg_replace('/:\d+$/', '', $host);

        return apply_filters('fluent_auth/passkey_rp_id', $host);
    }

    public static function getAllowedOrigins()
    {
        $origins = array_unique(array_filter([
            self::getOrigin(home_url()),
            self::getOrigin(site_url())
        ]));

        return apply_filters('fluent_auth/passkey_allowed_origins', $origins);
    }

    public static function getUserVerification()
    {
        $value = Helper::getSetting('passkey_user_verification', 'preferred');
        if (!in_array($value, ['required', 'preferred', 'discouraged'], true)) {
            $value = 'preferred';
        }

        return apply_filters('fluent_auth/passkey_user_verification', $value);
    }

    private static function parseClientData($encodedClientData, $type, $challenge)
    {
        $json = self::base64UrlDecode($encodedClientData);
        $data = json_decode($json, true);

        if (!$data || Arr::get($data, 'type') !== $type) {
            return new \WP_Error('invalid_client_data', __('Invalid passkey response.', 'fluent-security'), ['status' => 422]);
        }

        if (!hash_equals($challenge, Arr::get($data, 'challenge'))) {
            return new \WP_Error('invalid_challenge', __('The passkey challenge expired or could not be verified.', 'fluent-security'), ['status' => 422]);
        }

        if (!in_array(Arr::get($data, 'origin'), self::getAllowedOrigins(), true)) {
            return new \WP_Error('invalid_origin', __('This passkey request came from an invalid origin.', 'fluent-security'), ['status' => 422]);
        }

        return $data;
    }

    private static function parseAuthenticatorData($authData, $requiresAttestedData)
    {
        if (!$authData || strlen($authData) < 37) {
            throw new \Exception('Invalid authenticator data');
        }

        $offset = 0;
        $rpIdHash = substr($authData, $offset, 32);
        $offset += 32;
        $flags = ord($authData[$offset]);
        $offset += 1;
        $signCount = unpack('N', substr($authData, $offset, 4))[1];
        $offset += 4;

        $data = [
            'rp_id_hash' => $rpIdHash,
            'flags'      => $flags,
            'sign_count' => $signCount
        ];

        if (!$requiresAttestedData) {
            return $data;
        }

        if (!($flags & 0x40) || strlen($authData) < $offset + 18) {
            throw new \Exception('Missing attested credential data');
        }

        $aaguid = substr($authData, $offset, 16);
        $offset += 16;
        $credentialIdLength = unpack('n', substr($authData, $offset, 2))[1];
        $offset += 2;
        $credentialId = substr($authData, $offset, $credentialIdLength);
        $offset += $credentialIdLength;
        $credentialPublicKeyRaw = substr($authData, $offset);

        $data['aaguid'] = $aaguid;
        $data['credential_id'] = $credentialId;
        $data['credential_public_key_raw'] = $credentialPublicKeyRaw;
        $data['credential_public_key'] = self::decodeCbor($credentialPublicKeyRaw);

        return $data;
    }

    private static function storeChallenge($type, $challenge, $data = [])
    {
        $token = self::randomBase64Url(24);
        $data = wp_parse_args($data, [
            'type'      => $type,
            'challenge' => $challenge,
            'created'   => time()
        ]);

        set_transient(self::CHALLENGE_PREFIX . $token, $data, self::CHALLENGE_TTL);

        return $token;
    }

    private static function consumeChallenge($token, $type)
    {
        $token = sanitize_text_field($token);
        if (!$token) {
            return new \WP_Error('missing_challenge', __('The passkey challenge is missing.', 'fluent-security'), ['status' => 422]);
        }

        $key = self::CHALLENGE_PREFIX . $token;
        $data = get_transient($key);
        delete_transient($key);

        if (!$data || Arr::get($data, 'type') !== $type) {
            return new \WP_Error('invalid_challenge', __('The passkey challenge expired or could not be verified.', 'fluent-security'), ['status' => 422]);
        }

        return $data;
    }

    private static function coseKeyToPem($key)
    {
        $kty = Arr::get($key, 1);
        $alg = Arr::get($key, 3);

        if ($kty == 2 && $alg == -7) {
            $x = Arr::get($key, -2);
            $y = Arr::get($key, -3);
            if (strlen($x) !== 32 || strlen($y) !== 32) {
                return new \WP_Error('unsupported_passkey', __('This passkey type is not supported.', 'fluent-security'), ['status' => 422]);
            }

            $algorithm = self::derSequence(
                self::derOid(hex2bin('2A8648CE3D0201')) .
                self::derOid(hex2bin('2A8648CE3D030107'))
            );
            $subjectPublicKey = self::derBitString("\x04" . $x . $y);

            return [
                'alg' => -7,
                'pem' => self::derToPem(self::derSequence($algorithm . $subjectPublicKey), 'PUBLIC KEY')
            ];
        }

        if ($kty == 3 && $alg == -257) {
            $n = Arr::get($key, -1);
            $e = Arr::get($key, -2);
            if (!$n || !$e) {
                return new \WP_Error('unsupported_passkey', __('This passkey type is not supported.', 'fluent-security'), ['status' => 422]);
            }

            $rsaPublicKey = self::derSequence(self::derInteger($n) . self::derInteger($e));
            $algorithm = self::derSequence(self::derOid(hex2bin('2A864886F70D010101')) . "\x05\x00");

            return [
                'alg' => -257,
                'pem' => self::derToPem(self::derSequence($algorithm . self::derBitString($rsaPublicKey)), 'PUBLIC KEY')
            ];
        }

        return new \WP_Error('unsupported_passkey', __('This passkey algorithm is not supported.', 'fluent-security'), ['status' => 422]);
    }

    private static function opensslAlgorithm($alg)
    {
        return OPENSSL_ALGO_SHA256;
    }

    private static function getDefaultCredentialName($payload)
    {
        $ua = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '';
        $name = Arr::get($payload, 'name');

        if (!$name && $ua) {
            $name = substr($ua, 0, 90);
        }

        return $name ?: __('Passkey', 'fluent-security');
    }

    private static function isLocalhost()
    {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    }

    private static function getOrigin($url)
    {
        $scheme = wp_parse_url($url, PHP_URL_SCHEME);
        $host = wp_parse_url($url, PHP_URL_HOST);
        $port = wp_parse_url($url, PHP_URL_PORT);

        if (!$scheme || !$host) {
            return '';
        }

        $origin = $scheme . '://' . $host;
        if ($port) {
            $origin .= ':' . $port;
        }

        return $origin;
    }

    public static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode($data)
    {
        $data = strtr((string)$data, '-_', '+/');
        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }

        return base64_decode($data, true);
    }

    private static function randomBase64Url($length)
    {
        return self::base64UrlEncode(random_bytes($length));
    }

    private static function decodeCbor($data)
    {
        $offset = 0;
        return self::readCborItem($data, $offset);
    }

    private static function readCborItem($data, &$offset)
    {
        if ($offset >= strlen($data)) {
            throw new \Exception('Invalid CBOR');
        }

        $initial = ord($data[$offset++]);
        $major = $initial >> 5;
        $additional = $initial & 0x1f;
        $length = self::readCborLength($data, $offset, $additional);

        if ($major === 0) {
            return $length;
        }

        if ($major === 1) {
            return -1 - $length;
        }

        if ($major === 2) {
            $value = substr($data, $offset, $length);
            $offset += $length;
            return $value;
        }

        if ($major === 3) {
            $value = substr($data, $offset, $length);
            $offset += $length;
            return $value;
        }

        if ($major === 4) {
            $items = [];
            for ($i = 0; $i < $length; $i++) {
                $items[] = self::readCborItem($data, $offset);
            }
            return $items;
        }

        if ($major === 5) {
            $map = [];
            for ($i = 0; $i < $length; $i++) {
                $key = self::readCborItem($data, $offset);
                $map[$key] = self::readCborItem($data, $offset);
            }
            return $map;
        }

        if ($major === 7) {
            if ($additional === 20) {
                return false;
            }
            if ($additional === 21) {
                return true;
            }
            if ($additional === 22) {
                return null;
            }
        }

        throw new \Exception('Unsupported CBOR value');
    }

    private static function readCborLength($data, &$offset, $additional)
    {
        if ($additional < 24) {
            return $additional;
        }

        if ($additional === 24) {
            return ord($data[$offset++]);
        }

        if ($additional === 25) {
            $value = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;
            return $value;
        }

        if ($additional === 26) {
            $value = unpack('N', substr($data, $offset, 4))[1];
            $offset += 4;
            return $value;
        }

        throw new \Exception('Unsupported CBOR length');
    }

    private static function derToPem($der, $label)
    {
        return "-----BEGIN {$label}-----\n" .
            chunk_split(base64_encode($der), 64, "\n") .
            "-----END {$label}-----\n";
    }

    private static function derSequence($data)
    {
        return "\x30" . self::derLength(strlen($data)) . $data;
    }

    private static function derOid($oid)
    {
        return "\x06" . self::derLength(strlen($oid)) . $oid;
    }

    private static function derBitString($data)
    {
        return "\x03" . self::derLength(strlen($data) + 1) . "\x00" . $data;
    }

    private static function derInteger($data)
    {
        $data = ltrim($data, "\x00");
        if ($data === '' || (ord($data[0]) & 0x80)) {
            $data = "\x00" . $data;
        }

        return "\x02" . self::derLength(strlen($data)) . $data;
    }

    private static function derLength($length)
    {
        if ($length < 128) {
            return chr($length);
        }

        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
