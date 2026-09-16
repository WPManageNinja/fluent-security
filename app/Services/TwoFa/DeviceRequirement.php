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

        return (bool)apply_filters('fluent_auth/device_factor_required', true, $user);
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
