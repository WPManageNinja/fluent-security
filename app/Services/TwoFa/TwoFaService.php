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
     * The login screen action that trades an outstanding challenge for one the user can
     * actually answer.
     *
     * A second factor can be unanswerable through no fault of the account holder - a
     * passkey on a browser with no WebAuthn, a phone left at home - and a challenge form
     * with no way past it is a lockout whatever raised it. This is the way past it, and
     * it only ever moves sideways: the replacement has to prove the same factor, so
     * switching can never be a way to be asked for less.
     */
    const SWITCH_ACTION = 'fls_2fa_switch';

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
     * Where an outstanding challenge can be swapped for a different method.
     *
     * @param $hash string
     * @return string
     */
    public static function getSwitchUrl($hash)
    {
        return add_query_arg([
            'login_hash' => $hash,
            'action'     => self::SWITCH_ACTION
        ], wp_login_url());
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
         * Strongest first, and the order is the whole policy: the dispatcher asks for
         * the first method that fits, so this is what decides which one a user with
         * several enrolled actually sees.
         *
         * A passkey leads because the browser binds it to this site's domain, so it is
         * the only one of the three that a user standing on a convincing copy of the
         * login page cannot be talked through. An authenticator app follows - still
         * proof of a device, still unanswerable by whoever holds the mailbox, but six
         * digits that work wherever they are typed. A mailed code is last because it
         * proves only the mailbox, which is often the thing already lost.
         *
         * Enrollment sits between the device methods and the mailed code, and the
         * placement is the policy. Above email, because a user whose role must hold a
         * device factor has to go and get one rather than be waved through on a code to
         * an address - putting it below would let the weakest method satisfy a rule
         * written to demand the strongest, which is the rule meaning nothing. Below the
         * two real device methods, because somebody who already has one owes nothing:
         * both answer isAvailableForUser() first and this is never reached.
         */
        $registered = apply_filters('fluent_auth/2fa_methods', [
            new PasskeyTwoFaMethod(),
            new TotpTwoFaMethod(),
            new EnrollmentTwoFaMethod(),
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

        /*
         * The lockout escape, asked first so it covers every method equally - a lost
         * phone and a browser that cannot do WebAuthn are the same problem from here.
         * See TwoFaBypass: setting it needs write access to wp-config.php, which is
         * already more authority than any second factor protects.
         */
        if (TwoFaBypass::isActiveFor($user)) {
            return null;
        }

        if ($satisfiedFactors === null) {
            $satisfiedFactors = Helper::getSatisfiedFactors();
        }

        /*
         * A login that already proved a device owes nothing further.
         *
         * Every method below is either the same factor - skipped by the loop anyway - or
         * an emailed code, and a mailed code on top of a passkey is not a second factor
         * but a weaker first one repeated. The mailbox is where password resets arrive,
         * so asking for it after an authenticator has checked a fingerprint subtracts
         * from what the login proved rather than adding to it.
         *
         * Only the passwordless passkey route ever puts DEVICE in this set - a password
         * login declares KNOWLEDGE, magic login and social login declare EMAIL or IDP -
         * so this changes nothing for any flow that reaches it with the default. It is
         * the mirror of the rule those flows rely on: they proved something weaker than
         * a device and still owe one, this proved the device and owes none.
         *
         * A site that wants a mailed code even here can say so through the filter, which
         * is also the escape hatch for anyone who reads AAL2 more strictly than FIDO does.
         */
        if (in_array(AuthFactor::DEVICE, (array)$satisfiedFactors, true)
            && apply_filters('fluent_auth/device_factor_completes_login', true, $user, $satisfiedFactors)) {
            return null;
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
     * Another method this user could answer instead of the one they were given.
     *
     * Constrained to methods proving the same factor as the one being replaced. Letting
     * a user swap a device factor for a mailed code would turn every challenge into an
     * invitation to downgrade it, which is the opposite of what getRequiredMethod()
     * spends its time preventing.
     *
     * @param $user \WP_User
     * @param $current BaseTwoFaMethod
     * @return BaseTwoFaMethod|null
     */
    public static function getAlternativeMethod($user, $current)
    {
        if (!$user instanceof \WP_User || !$current instanceof BaseTwoFaMethod) {
            return null;
        }

        foreach (self::getMethods() as $method) {
            if ($method->getKey() === $current->getKey()) {
                continue;
            }

            if ($method->getSatisfiedFactor() !== $current->getSatisfiedFactor()) {
                continue;
            }

            if ($method->isAvailableForUser($user)) {
                return $method;
            }
        }

        return null;
    }

    /**
     * @return void
     */
    public static function resetMethods()
    {
        self::$methods = null;
    }
}
