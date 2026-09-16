<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\IpRules;
use FluentAuth\App\Services\TwoFa\WebAuthn\Assertion;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\Ceremony;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\RelyingParty;
use FluentAuth\App\Services\TwoFa\WebAuthn\WebAuthnException;

/**
 * Signing in with a passkey and nothing else.
 *
 * The second factor flow in PasskeyTwoFaMethod already knows who is signing in - a
 * password got them that far - so it can hand the browser a list of that account's
 * credentials to choose from. Here nobody has said who they are yet, which changes one
 * thing in the ceremony and everything about what has to be checked afterwards.
 *
 * The one change is an empty allowCredentials list. That asks the authenticator to look
 * through what it holds for this domain and offer whatever it finds, which is what makes
 * the button work without a username. Only a discoverable credential can answer, and
 * Registration asks for `residentKey: preferred`, so most passkeys registered here can.
 *
 * What it costs is that the account arrives from the reply rather than from the request,
 * so the credential id the browser returns is the only thing pointing at a user. That is
 * safe because the id is looked up in this site's own table and the signature is then
 * checked against the public key stored in that row: naming somebody else's credential
 * gets you their public key to forge against, which is the thing the private key exists
 * to make impossible.
 */
class PasskeyLogin
{
    /**
     * Prefix for the transient holding an issued challenge.
     */
    const CHALLENGE_PREFIX = 'fls_pk_login_';

    /**
     * How long an issued challenge stays answerable, in seconds.
     *
     * Short because nothing about this flow needs longer - the browser raises the
     * platform prompt straight away - and because an unspent challenge is the one piece
     * of state an anonymous caller can make the site create.
     */
    const CHALLENGE_TTL = 300;

    /**
     * Whether the login form should offer a passkey at all.
     *
     * @return bool
     */
    public static function isPrimaryLoginEnabled()
    {
        /*
         * Asked without going through PasskeyTwoFaMethod::isEnabledForAnyRole(), which
         * now asks this - the two would call each other forever. The conditions that
         * matter here are the settings and the platform, and both are read directly.
         */
        if (Helper::getSetting('passkey_2fa') !== 'yes') {
            return false;
        }

        if (Helper::getSetting('passkey_primary_login') !== 'yes') {
            return false;
        }

        /*
         * Over plain http no passkey can be read back, so the button would be an offer
         * the browser refuses. This is the same secure-context test registration makes.
         */
        if (!RelyingParty::isSupported()) {
            return false;
        }

        return (bool)apply_filters('fluent_auth/passkey_primary_login', true);
    }

    /**
     * Builds a challenge for a browser that has not said who it is.
     *
     * @return array|\WP_Error ['token' => string, 'options' => array]
     */
    public static function issueChallenge()
    {
        if (!self::isPrimaryLoginEnabled()) {
            return new \WP_Error(
                'passkey_login_disabled',
                __('Signing in with a passkey is not available on this site.', 'fluent-security')
            );
        }

        try {
            $challenge = Ceremony::createChallenge();
            $token = Base64Url::encode(random_bytes(32));
        } catch (\Exception $e) {
            return new \WP_Error(
                'passkey_no_randomness',
                __('This site cannot start a passkey sign in right now.', 'fluent-security')
            );
        }

        set_transient(self::CHALLENGE_PREFIX . $token, Base64Url::encode($challenge), self::CHALLENGE_TTL);

        /*
         * An empty credential list is the whole difference from the second factor flow -
         * see the class comment. Passed as an empty array rather than by building the
         * options by hand so that anything filtering webauthn_request_options sees this
         * ceremony too.
         */
        $options = Assertion::getRequestOptions($challenge, []);

        return [
            'token'   => $token,
            'options' => $options
        ];
    }

    /**
     * Checks an assertion offered in place of a password and signs the user in.
     *
     * @param $token string the value issueChallenge() handed out
     * @param $response array the browser's reply, already decoded
     * @return \WP_User|\WP_Error
     */
    public static function authenticate($token, $response)
    {
        if (!self::isPrimaryLoginEnabled()) {
            return new \WP_Error(
                'passkey_login_disabled',
                __('Signing in with a passkey is not available on this site.', 'fluent-security')
            );
        }

        $challenge = self::consumeChallenge($token);

        if ($challenge === '') {
            return new \WP_Error(
                'passkey_expired',
                __('This sign in attempt has expired. Please try again.', 'fluent-security')
            );
        }

        $rawId = Arr::get($response, 'rawId');
        $credential = PasskeyStore::findByCredentialId(is_string($rawId) ? $rawId : '');

        if (!$credential) {
            return self::refuse('passkey_unknown');
        }

        $user = get_user_by('ID', (int)$credential->user_id);

        if (!$user instanceof \WP_User) {
            return self::refuse('passkey_orphaned');
        }

        /*
         * The account has to still be one this site would let hold a passkey. A role
         * demoted after registration, or a `fluent_auth/passkey_enabled` filter that has
         * since changed its mind, both land here - and a credential nobody is allowed to
         * use any more must not keep working just because the row survived.
         */
        if (!PasskeyTwoFaMethod::isAllowedForUser($user)) {
            return self::refuse('passkey_not_allowed', $user);
        }

        /*
         * The two address rules that apply to every route in, checked here because this
         * one never reaches `authenticate` and so never meets LoginSecurityHandler.
         *
         * The guess-based rate limit deliberately is not among them. It counts wrong
         * passwords, and there is no wrong answer to count here: an assertion either
         * carries a signature made by a private key this site holds the public half of,
         * or it is discarded without telling anyone anything. Applying a limit built for
         * guessing would only give an attacker a way to lock a passkey holder out by
         * failing on their behalf.
         */
        if (IpRules::deniesSignIn($user)) {
            return self::refuse('passkey_location_blocked', $user);
        }

        if (IpRules::blockingRule(Helper::getIp())) {
            return self::refuse('passkey_ip_blocked', $user);
        }

        try {
            $signCount = Assertion::verify($response, $credential, $challenge, $user);
        } catch (WebAuthnException $e) {
            do_action('fluent_auth/passkey_verification_failed', $user, $e->getMessage());

            return self::refuse('passkey_rejected', $user);
        }

        PasskeyStore::touch($credential, $signCount);

        /*
         * Declared before the cookie is minted, because TwoFaHandler reads it from
         * `send_auth_cookies` to decide whether this login still owes a factor.
         *
         * DEVICE because that is exactly what an authenticator just proved. KNOWLEDGE
         * because Ceremony::getUserVerificationRequirement() defaults to `required`, so
         * the device checked a fingerprint, a face or a PIN before it would sign -
         * which is the thing a password is for, collected by something that cannot be
         * phished. Where a site has lowered that requirement the gesture was not
         * checked, only possession was, and the claim is narrowed to match.
         */
        $factors = [AuthFactor::DEVICE];

        if (Ceremony::isUserVerificationRequired()) {
            $factors[] = AuthFactor::KNOWLEDGE;
        }

        Helper::setSatisfiedFactors($factors);

        /*
         * Named in the audit log as its own route in. Left alone it reads as 'web', which
         * is the password form - and a sign in that never involved a password being
         * recorded as one is the log misleading whoever reads it looking for how an
         * account was reached.
         */
        Helper::setLoginMedia('passkey_login');

        $signedIn = AuthService::makeLogin($user, 'passkey');

        if (is_wp_error($signedIn)) {
            return $signedIn;
        }

        do_action('fluent_auth/passkey_verified', $user, $credential);
        do_action('fluent_auth/passkey_login_completed', $user, $credential);

        return $signedIn;
    }

    /**
     * Reads an issued challenge and spends it.
     *
     * Deleted whether or not what follows succeeds, which is what stops one challenge
     * being replayed against a captured assertion.
     *
     * @param $token string
     * @return string raw bytes, empty when the token is unknown or expired
     */
    private static function consumeChallenge($token)
    {
        $token = (string)$token;

        // The token is base64url this site generated; anything else cannot match a key.
        if ($token === '' || !preg_match('/^[A-Za-z0-9_-]{16,128}$/', $token)) {
            return '';
        }

        $key = self::CHALLENGE_PREFIX . $token;
        $stored = get_transient($key);

        delete_transient($key);

        if (!is_string($stored) || $stored === '') {
            return '';
        }

        $challenge = Base64Url::decode($stored);

        return $challenge === false ? '' : $challenge;
    }

    /**
     * One answer for every way this can fail.
     *
     * Which check refused is recorded for the site and withheld from the browser. An
     * unknown credential, a demoted role and a bad signature are all the same sentence
     * out here, because telling an anonymous caller which one it was turns the login
     * form into a way to ask whether a given passkey is registered.
     *
     * @param $reason string
     * @param $user \WP_User|null
     * @return \WP_Error
     */
    private static function refuse($reason, $user = null)
    {
        do_action('fluent_auth/passkey_login_refused', $reason, $user);

        return new \WP_Error(
            'passkey_login_failed',
            __('That passkey could not be used to sign in here.', 'fluent-security')
        );
    }
}
