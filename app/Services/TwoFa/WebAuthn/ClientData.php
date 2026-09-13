<?php

namespace FluentAuth\App\Services\TwoFa\WebAuthn;

/**
 * The clientDataJSON block, which is the browser's account of what it was asked to do.
 *
 * It is the browser speaking rather than the authenticator, and it is covered by the
 * signature, so it is where three of the load bearing checks live: that the challenge
 * is the one this site issued, that the origin is this site, and that the ceremony was
 * the one being run.
 *
 * That last one matters more than it looks. Registration and authentication produce
 * structurally similar material, and `type` is the only thing separating them - without
 * checking it, an assertion collected from a user on some other site could be
 * presented here as a registration.
 */
class ClientData
{
    const TYPE_CREATE = 'webauthn.create';

    const TYPE_GET = 'webauthn.get';

    /** @var string */
    private $raw;

    /** @var array */
    private $decoded;

    /**
     * @param $json string
     * @throws WebAuthnException
     */
    public function __construct($json)
    {
        if (!is_string($json) || $json === '') {
            throw new WebAuthnException('Client data is empty');
        }

        $decoded = json_decode($json, true);

        if (!is_array($decoded)) {
            throw new WebAuthnException('Client data is not valid JSON');
        }

        $this->raw = $json;
        $this->decoded = $decoded;
    }

    /**
     * Runs every check this block is responsible for.
     *
     * @param $expectedType string
     * @param $expectedChallenge string the raw bytes as issued, not the encoded form
     * @param $allowedOrigins array
     * @return void
     * @throws WebAuthnException
     */
    public function verify($expectedType, $expectedChallenge, $allowedOrigins)
    {
        $type = isset($this->decoded['type']) ? $this->decoded['type'] : '';

        if (!is_string($type) || !hash_equals($expectedType, $type)) {
            throw new WebAuthnException('Client data is for a different ceremony');
        }

        $challenge = isset($this->decoded['challenge']) ? $this->decoded['challenge'] : '';
        $challenge = is_string($challenge) ? Base64Url::decode($challenge) : false;

        if ($challenge === false || $expectedChallenge === '') {
            throw new WebAuthnException('Client data carries no readable challenge');
        }

        if (!hash_equals($expectedChallenge, $challenge)) {
            throw new WebAuthnException('Client data challenge does not match the one issued');
        }

        $origin = isset($this->decoded['origin']) ? $this->decoded['origin'] : '';

        if (!is_string($origin) || !self::matchesOrigin($origin, $allowedOrigins)) {
            throw new WebAuthnException('Client data origin is not this site');
        }

        /*
         * A ceremony run from inside a cross-origin frame is refused. The browser will
         * have shown the user a prompt naming this site while the page around it belongs
         * to someone else, which is the setup for having someone sign in to an account
         * they did not mean to.
         */
        if (!empty($this->decoded['crossOrigin'])) {
            throw new WebAuthnException('Client data reports a cross-origin ceremony');
        }
    }

    /**
     * An exact match against a known origin, never a prefix or suffix one.
     *
     * Comparing loosely here is the classic way to lose the whole scheme:
     * "https://example.com.attacker.test" ends with nothing useful, but it does begin
     * with something that a careless starts-with check would accept.
     *
     * @param $origin string
     * @param $allowedOrigins array
     * @return bool
     */
    private static function matchesOrigin($origin, $allowedOrigins)
    {
        foreach ((array)$allowedOrigins as $allowed) {
            if (is_string($allowed) && $allowed !== '' && hash_equals($allowed, $origin)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return string
     */
    public function getRaw()
    {
        return $this->raw;
    }

    /**
     * The hash that the authenticator signed alongside its own data.
     *
     * @return string
     */
    public function getHash()
    {
        return hash('sha256', $this->raw, true);
    }
}
