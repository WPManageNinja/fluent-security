<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * Contract for a second factor.
 *
 * An implementation owns only the proof itself: producing it, rendering its form and
 * checking it. Everything wrapped around it - the pending login row, the redirect
 * intent, the remember-me flag, the attempt cap and the final sign in - stays in
 * TwoFaHandler, so adding a method never means reimplementing the login flow.
 */
abstract class BaseTwoFaMethod
{
    /**
     * Recorded in fls_login_hashes.use_type, which is varchar(20).
     *
     * @return string
     */
    abstract public function getKey();

    /**
     * @return string
     */
    abstract public function getTitle();

    /**
     * What this method proves. See AuthFactor.
     *
     * @return string
     */
    abstract public function getSatisfiedFactor();

    /**
     * Whether this user can be challenged with this method right now - enabled for
     * their role, or enrolled in it.
     *
     * @param $user \WP_User
     * @return bool
     */
    abstract public function isAvailableForUser($user);

    /**
     * Whether this user has registered this method, whether or not it can be asked of
     * them right now.
     *
     * The same answer as isAvailableForUser() for every method but one, and that one is
     * why this exists: a lone passkey is enrolled and not available, because there is
     * nothing behind it to fall back on. A screen offering the user that fallback has to
     * be able to see the credential that needs it - measuring enrollment with
     * availability is what left such an account with no way out of the state it was in.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public function isEnrolledForUser($user)
    {
        return $this->isAvailableForUser($user);
    }

    /**
     * The use_type recorded when the challenge was raised because the account is under
     * attack rather than because the method is switched on. Methods that need no
     * separate marker just reuse their own key.
     *
     * @return string
     */
    public function getChallengeKey()
    {
        return $this->getKey();
    }

    /**
     * Whether this method can be forced on a user who has not set it up.
     *
     * An account under attack is challenged even where the method is switched off for
     * its role, but that only works for a method whose proof the site can produce on
     * demand - a code to the address already on the account. A method resting on
     * something the user registered in advance cannot: challenging someone with an
     * authenticator app they never enrolled in presents a form no one alive can answer,
     * which is a lockout, not a defence.
     *
     * Off by default, so a new method has to say it can do this rather than inherit it.
     *
     * @return bool
     */
    public function supportsUnenrolledChallenge()
    {
        return false;
    }

    /**
     * Builds the proof.
     *
     * Returns `columns` to merge into the pending login row (a hashed code, a WebAuthn
     * challenge, or nothing for a method that needs no server side state) and `secret`,
     * the plaintext to hand to dispatchChallenge. The secret is never persisted.
     *
     * @param $user \WP_User
     * @return array
     */
    public function prepareChallenge($user)
    {
        return [
            'columns' => [],
            'secret'  => null
        ];
    }

    /**
     * Runs once the pending row exists, for anything with a side effect - sending the
     * code email, for instance. A method whose proof already lives on the user's device
     * has nothing to do here.
     *
     * @param $user \WP_User
     * @param $challenge array as returned by prepareChallenge()
     * @param $context array login_hash, redirect_to and the row that was written
     * @return void
     */
    public function dispatchChallenge($user, $challenge, $context)
    {
    }

    /**
     * @param $data array
     * @return string
     */
    abstract public function renderForm($data);

    /**
     * Checks the submitted proof.
     *
     * Returning false is a wrong answer and counts against the attempt cap. A WP_Error
     * is a hard failure - malformed input, an unusable credential - and does not.
     *
     * @param $user \WP_User
     * @param $logHash object
     * @param $request array
     * @return bool|\WP_Error
     */
    abstract public function verifyProof($user, $logHash, $request);

    /**
     * The JSON a completed sign in answers with.
     *
     * Almost every method wants exactly one thing here - where to go next - and takes
     * this as it stands. It exists for the one that has something to say before the
     * browser leaves the page: enrollment finishes by handing over recovery codes, and
     * those are shown once or never, so redirecting straight past them would lose the
     * only copy the user will ever be offered.
     *
     * @param $response array
     * @param $user \WP_User
     * @param $logHash object
     * @return array
     */
    public function getSuccessResponse($response, $user, $logHash)
    {
        return $response;
    }

    /**
     * Recorded on the auth log so an admin can see which factor was actually used.
     *
     * @return string
     */
    public function getLoginMedia()
    {
        return 'two_factor_' . $this->getKey();
    }

    /**
     * One sentence telling a user, from inside somebody else's login form, what has just
     * happened and what they hold that answers it. The link to the form is added by the
     * caller.
     *
     * @return string
     */
    public function getHandoffText()
    {
        return __('One more step is needed to finish signing in.', 'fluent-security');
    }
}
