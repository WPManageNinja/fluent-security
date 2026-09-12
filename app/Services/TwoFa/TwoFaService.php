<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Helper;

/**
 * Registry of second factor methods, and the rule for picking one.
 */
class TwoFaService
{
    /**
     * The wp-login.php action that shows a challenge form.
     *
     * Named for what it does rather than for the one method that used to do it: an
     * authenticator app is answered on this same screen, and a login recorded as
     * `fls_2fa_email` while no email was ever sent reads as a bug to whoever is
     * following it through the logs.
     *
     * This replaces that name outright rather than joining it. Both went out in 2.1.0,
     * so anything hooking `login_form_fls_2fa_email` or posting to the old admin-ajax
     * action stops working - a breaking change, taken deliberately, and one for the
     * changelog of whichever release carries it.
     */
    const LOGIN_ACTION = 'fls_2fa_verify';

    /**
     * The admin-ajax action the form posts its answer to.
     */
    const AJAX_ACTION = 'fluent_auth_2fa_verify';

    /**
     * Marks a login screen request as a challenge rather than an ordinary sign in. Its
     * value is not read - see maybeResumePendingChallenge(), which only asks whether the
     * browser is already on the form.
     */
    const CHALLENGE_MARKER = 'verify';

    private static $methods = null;

    /**
     * Where a pending challenge is answered.
     *
     * The one place this URL is shaped. It used to be spelled out both here and in the
     * emailed auto-login link, which is two places to keep in step.
     *
     * @param $hash string
     * @param $extra array extra query arguments, such as an emailed code
     * @return string
     */
    public static function getChallengeUrl($hash, $extra = [])
    {
        return add_query_arg(array_merge([
            'fls_2fa'    => self::CHALLENGE_MARKER,
            'login_hash' => $hash,
            'action'     => self::LOGIN_ACTION
        ], $extra), wp_login_url());
    }

    /**
     * Registered methods, keyed by method key.
     *
     * Order is significant: the dispatcher asks for the first one that fits, so a
     * stronger factor registered ahead of a weaker one wins.
     *
     * @return BaseTwoFaMethod[]
     */
    public static function getMethods()
    {
        if (self::$methods !== null) {
            return self::$methods;
        }

        $methods = [];

        /*
         * An authenticator app comes first deliberately. Where a user has enrolled one
         * it is the stronger of the two, and it is the one an attacker holding the
         * mailbox cannot answer - so it should be what they are asked for, not a code
         * mailed to an address that may already be lost.
         */
        $registered = apply_filters('fluent_auth/2fa_methods', [
            new TotpTwoFaMethod(),
            new EmailTwoFaMethod()
        ]);

        foreach ($registered as $method) {
            if ($method instanceof BaseTwoFaMethod) {
                $methods[$method->getKey()] = $method;
            }
        }

        self::$methods = $methods;

        return self::$methods;
    }

    /**
     * Resolves the method that owns a pending row, by its use_type.
     *
     * A row raised as a challenge carries the method's challenge key rather than its
     * own key, so both have to resolve back to the same method.
     *
     * @param $useType string
     * @return BaseTwoFaMethod|null
     */
    public static function getMethodByUseType($useType)
    {
        foreach (self::getMethods() as $method) {
            if ($useType === $method->getKey() || $useType === $method->getChallengeKey()) {
                return $method;
            }
        }

        return null;
    }

    /**
     * Every use_type that belongs to a second factor, for querying the hashes table.
     *
     * @return array
     */
    public static function getAllUseTypes()
    {
        $useTypes = [];

        foreach (self::getMethods() as $method) {
            $useTypes[] = $method->getKey();
            $useTypes[] = $method->getChallengeKey();
        }

        return array_values(array_unique($useTypes));
    }

    /**
     * The method this user still owes, given what the first step already proved.
     *
     * A method proving the same factor as the first step is skipped - an emailed code
     * after a magic link is the same mailbox twice, so it adds nothing. Anything proving
     * a different factor is still required however the user got here, which is what
     * keeps magic login from becoming a way around an authenticator app.
     *
     * @param $user \WP_User
     * @param $satisfiedFactors array|null
     * @param $challengeRequired bool|callable whether the account is under attack. A
     *                                         callable is only invoked if the answer can
     *                                         still change the outcome - measuring it
     *                                         costs two queries over the auth log, and
     *                                         a user with an enrolled method is getting
     *                                         that method either way.
     * @return BaseTwoFaMethod|null
     */
    public static function getRequiredMethod($user, $satisfiedFactors = null, $challengeRequired = false)
    {
        if (!$user instanceof \WP_User) {
            return null;
        }

        if ($satisfiedFactors === null) {
            $satisfiedFactors = Helper::getSatisfiedFactors();
        }

        $fallback = null;
        $underAttack = null;

        foreach (self::getMethods() as $method) {
            if (in_array($method->getSatisfiedFactor(), (array)$satisfiedFactors, true)) {
                continue;
            }

            if ($method->isAvailableForUser($user)) {
                return $method;
            }

            /*
             * An account under attack is challenged even where the method is switched
             * off for its role - but only with a method that proves something the first
             * step did not, and only one the site can raise for a user who never set it
             * up. Someone who arrived by magic link has already shown they hold the
             * mailbox, which is the very thing the challenge exists to ask for; someone
             * with no authenticator app enrolled cannot be shown its form at all.
             *
             * The free tests come first so that asking whether the account is under
             * attack - the expensive one - is skipped entirely where no method could
             * answer the challenge anyway.
             */
            if ($fallback === null && $method->supportsUnenrolledChallenge()) {
                if ($underAttack === null) {
                    $underAttack = is_callable($challengeRequired)
                        ? (bool)call_user_func($challengeRequired)
                        : (bool)$challengeRequired;
                }

                if ($underAttack) {
                    $fallback = $method;
                }
            }
        }

        return $fallback;
    }

    /**
     * @return void
     */
    public static function resetMethods()
    {
        self::$methods = null;
    }
}
