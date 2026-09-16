<?php

namespace FluentAuth\App\Services\TwoFa;

use FluentAuth\App\Helpers\Helper;

/**
 * Who has to hold a registered device, and whether they still owe one.
 *
 * The rule used to be written in terms of one method - an authenticator app - which
 * made it two things at once: a policy about how strongly an account must be protected,
 * and an instruction about which product to use. Separating them matters because the
 * two have different right answers. The policy is "this role must prove a device";
 * whether that device is a passkey or an authenticator app is the user's business, and
 * a user who registered a passkey had already satisfied the policy while the old code
 * went on demanding an app from them.
 *
 * So the question is asked here, once, in terms of AuthFactor::DEVICE, and every screen
 * that used to ask TotpTwoFaMethod asks this instead.
 */
class DeviceRequirement
{
    /**
     * A passkey or an authenticator app. Nothing weaker counts.
     */
    const LEVEL_DEVICE = 'device';

    /**
     * Those, or an emailed code.
     */
    const LEVEL_ANY = 'any';

    /**
     * The roles named by the site owner.
     *
     * Still read from `totp_required_roles`. The key is now a misnomer - it governs
     * every device factor, not just the app - but it is what 10,000 sites already have
     * written in their options row, and a site that asked for a second factor on its
     * administrators still means that whatever the column is called. Renaming it would
     * mean a migration whose only failure mode is silently switching the requirement
     * off, which is the one outcome worth avoiding.
     *
     * @return array
     */
    public static function getRequiredRoles()
    {
        $roles = Helper::getSetting('totp_required_roles');

        return (is_array($roles) && $roles) ? array_values($roles) : [];
    }

    /**
     * How strong a factor this site will accept as meeting the requirement.
     *
     * `device` - a passkey or an authenticator app, and nothing else.
     * `any`    - those, or an emailed code, where emailed codes are actually configured
     *            for the role. The floor says what *counts*; it does not switch a method
     *            on. Reading it the other way made the requirement circular - email was
     *            granted to every required user, which satisfied the requirement, which
     *            meant nobody was ever asked for anything at that level.
     *
     * Two levels rather than a per-method matrix, because strength is the only part of
     * this the site owner is in a position to decide. Whether a given user can do a
     * passkey depends on their browser, their device and the moment; an owner choosing
     * "passkey" for a role is guessing about hardware they cannot see. What they do know
     * is how much they are willing to trade for fewer support calls, and that is this.
     *
     * `any` is weaker on purpose and worth having anyway: the realistic alternative for
     * an owner whose users cannot manage a device factor is not a stronger requirement,
     * it is no requirement at all.
     *
     * @return string
     */
    public static function getLevel()
    {
        $level = Helper::getSetting('two_fa_required_level');

        return $level === self::LEVEL_ANY ? self::LEVEL_ANY : self::LEVEL_DEVICE;
    }

    /**
     * Whether this user's role owes a second factor.
     *
     * Only the role list is asked, and deliberately no longer "is there a method they
     * could use". That check used to be here as an anti-lockout guard, and removing it
     * is safe now only because requiring a factor *grants* the methods that satisfy it -
     * see TotpTwoFaMethod::isAllowedForUser(). An authenticator app needs nothing from
     * the site at all: no https, no WebAuthn, no modern browser. So a required user
     * always has at least one path, guaranteed by construction rather than by a settings
     * check that could disagree with the enrollment screen.
     *
     * It also has to be asked without consulting any method, or the two would call each
     * other: a method asks whether the user is required in order to answer whether it is
     * allowed.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isRequiredForUser($user)
    {
        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        /*
         * Asked here as well as in the dispatcher, because this is what the backstop
         * reads. Lifting the requirement at the login screen while still refusing the
         * same person's REST calls afterwards would be a door unlocked onto a wall.
         */
        if (TwoFaBypass::isActiveFor($user)) {
            return false;
        }

        $roles = self::getRequiredRoles();

        if (!$roles || !array_intersect($roles, array_values($user->roles))) {
            return false;
        }

        /*
         * Asked of this user, not of the site. A method being switched on somewhere is
         * not the same as this person being able to reach it: emailed codes are on for
         * administrators while an editor is required, and the editor can get nothing.
         * Requiring a factor of somebody who has no way to obtain one is a locked out
         * account, which is the one outcome this rule must never produce.
         */
        if (!self::canBeSatisfiedBy($user)) {
            return false;
        }

        return (bool)apply_filters('fluent_auth/device_factor_required', true, $user);
    }

    /**
     * Whether this user could actually obtain something that meets the requirement.
     *
     * The site-level question - is any method on at all - is isEnforceable(), and it is
     * what the settings screen draws. This is the one enforcement reads, because the two
     * differ exactly where somebody gets locked out:
     *
     *   level = any, emailed codes on for administrators, editors required,
     *   authenticator app off, passkeys off
     *
     * isEnforceable() says yes, an accepted method is switched on. For an editor it is
     * unreachable - not their role's list - and the two device methods are off, so they
     * are marched to an enrolment screen that cannot give them anything. They pair an
     * app, it activates, they still owe a factor, and the next sign-in regenerates the
     * secret and kills the app they just paired.
     *
     * The two kinds of method are asked differently, and they have to be:
     *
     * - A device method is *granted* by the requirement, so being switched on is enough.
     *   Asking isAllowedForUser() here would call back into isRequiredForUser() and spin.
     * - An emailed code is not granted by anything. It reaches exactly the roles named on
     *   its own list, so that list is what decides, and isAvailableForUser() reads it
     *   without consulting the requirement.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function canBeSatisfiedBy($user)
    {
        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        /*
         * Re-entrancy, not caching. isPermittedForUser() runs site code -
         * `fluent_auth/totp_enabled` and its passkey twin - and a filter written as "the
         * app is for people who are required to hold one" calls isRequiredForUser(),
         * which is answered by this. Left open that is a stack overflow on one user's
         * login. Answering true to the inner call is the safe side: the outer one is
         * still deciding, and a requirement that stands where it should not is a prompt,
         * while one that falls where it should not is an account nobody is protecting.
         */
        static $answering = [];

        if (isset($answering[$user->ID])) {
            return true;
        }

        $answering[$user->ID] = true;

        try {
            return self::resolveSatisfiable($user);
        } finally {
            unset($answering[$user->ID]);
        }
    }

    /**
     * The body of canBeSatisfiedBy(), separated so the guard above always unwinds.
     *
     * @param $user \WP_User
     * @return bool
     */
    private static function resolveSatisfiable($user)
    {
        $accepted = self::getAcceptedFactors();

        foreach (TwoFaService::getMethods() as $method) {
            if (!in_array($method->getSatisfiedFactor(), $accepted, true) || !$method->isSwitchedOn()) {
                continue;
            }

            if ($method->isGrantedByRequirement()) {
                if ($method->isPermittedForUser($user)) {
                    return true;
                }

                continue;
            }

            if ($method->isAvailableForUser($user)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether anything on this site could satisfy the requirement.
     *
     * A requirement is a statement about the methods, not a method of its own. With every
     * switch down there is no second factor on the site at all, and "these roles must hold
     * one" over nothing would leave an owner looking at a screen where three methods read
     * off while two of them were quietly on for the required roles - which is the state
     * this question exists to stop being possible.
     *
     * So the requirement follows the switches: turn a method on and it can be required,
     * turn them all off and there is nothing to require. The settings screen says the same
     * thing in the same order, disabling the block rather than letting it be set over
     * nothing.
     *
     * The level is read here too, because it narrows what counts. At the device floor an
     * emailed code cannot satisfy anybody, so a site with only email codes on has nothing
     * that meets a device requirement - and the screen offers the weaker floor rather than
     * a requirement that cannot be met.
     *
     * Note what this does *not* read: role lists. A method that is on is available to a
     * required role whatever its own list says - see TotpTwoFaMethod::isAllowedForUser().
     * Asking the lists here would put the two back in a position to disagree, and a
     * disagreement between them is a user who must hold a factor and cannot get one.
     *
     * @return bool
     */
    public static function isEnforceable()
    {
        $accepted = self::getAcceptedFactors();

        foreach (TwoFaService::getMethods() as $method) {
            if (!in_array($method->getSatisfiedFactor(), $accepted, true)) {
                continue;
            }

            if ($method->isSwitchedOn()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a device factor could actually be asked of this user right now.
     *
     * Deliberately "available" rather than "enrolled", and the difference is not
     * academic. PasskeyTwoFaMethod::isAvailableForUser() also requires hasFallback(),
     * so a user holding exactly one passkey and no recovery codes is enrolled but will
     * never be challenged with it. Reading that as satisfied would let precisely the
     * user the policy is about sign in on a password alone - the enrolment would have
     * bought them an exemption rather than a second factor.
     *
     * Asked of the registry rather than of a hard coded pair, so a method added later
     * counts the day it is registered.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isSatisfiedBy($user)
    {
        return self::holdsAnyOf(self::resolveUser($user), self::getAcceptedFactors());
    }

    /**
     * Whether this user holds a passkey or an authenticator app, whatever the floor says.
     *
     * Separate from isSatisfiedBy() because the floor is a statement about *required*
     * roles, and reading it anywhere else lets it reach people it was never about: the
     * nudge asks this, so relaxing the floor for administrators cannot quietly stop every
     * ordinary subscriber being offered an authenticator app.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function hasDeviceFactor($user)
    {
        return self::holdsAnyOf(self::resolveUser($user), [AuthFactor::DEVICE]);
    }

    /**
     * Whether this user has a passkey or an authenticator app registered at all.
     *
     * Weaker than hasDeviceFactor() by exactly one case, and the case is the point: a
     * user holding one passkey and nothing else has a credential the login flow will
     * not ask for, so hasDeviceFactor() rightly answers no. Asking that before handing
     * out recovery codes closed the only door out of that state - the codes are what
     * would make the passkey usable, and they were refused on the grounds that it was
     * not usable yet.
     *
     * Nothing may be *required* of an account on the strength of this. It answers one
     * question: is there a device here that a set of recovery codes would be the way
     * back in for.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function holdsEnrolledDevice($user)
    {
        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        foreach (TwoFaService::getMethods() as $method) {
            // See holdsAnyOf(): asking the enrollment method would nest it in its own answer.
            if ($method instanceof EnrollmentTwoFaMethod) {
                continue;
            }

            if ($method->getSatisfiedFactor() !== AuthFactor::DEVICE) {
                continue;
            }

            if ($method->isEnrolledForUser($user)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param $user \WP_User|false
     * @param $factors array
     * @return bool
     */
    private static function holdsAnyOf($user, $factors)
    {
        if (!$user) {
            return false;
        }

        foreach (TwoFaService::getMethods() as $method) {
            /*
             * The enrollment method reports DEVICE too - it is what the user ends up
             * holding - and asking it would put this function inside its own answer.
             */
            if ($method instanceof EnrollmentTwoFaMethod) {
                continue;
            }

            if (!in_array($method->getSatisfiedFactor(), $factors, true)) {
                continue;
            }

            if ($method->isAvailableForUser($user)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The factors that count as meeting the requirement, at the level in force.
     *
     * @return array
     */
    public static function getAcceptedFactors()
    {
        if (self::getLevel() === self::LEVEL_ANY) {
            return [AuthFactor::DEVICE, AuthFactor::EMAIL];
        }

        return [AuthFactor::DEVICE];
    }

    /**
     * Required, and not yet met.
     *
     * @param $user \WP_User|int
     * @return bool
     */
    public static function isOwedBy($user)
    {
        $user = self::resolveUser($user);

        if (!$user) {
            return false;
        }

        return self::isRequiredForUser($user) && !self::isSatisfiedBy($user);
    }

    /**
     * @param $user \WP_User|int
     * @return \WP_User|false
     */
    private static function resolveUser($user)
    {
        if ($user instanceof \WP_User) {
            return $user;
        }

        if (!is_numeric($user)) {
            return false;
        }

        $resolved = get_user_by('ID', (int)$user);

        return $resolved instanceof \WP_User ? $resolved : false;
    }
}
