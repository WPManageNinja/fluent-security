/**
 * Whether the settings about to be saved lock the person saving them out.
 *
 * Every other field on the settings screen is somebody else's problem to discover. This
 * one is the reader's own, immediately: `totp_required_roles` including their own role
 * means their very next request is refused until they enroll - see
 * TotpEnforcementHandler::maybeDenyRest() - and the screen used to say so only in a note
 * above the Save button, which is the one place nobody reads twice.
 *
 * So Save asks first. Not a refusal: requiring a factor of yourself is a perfectly
 * ordinary thing to do, and the right answer is usually yes. It is a confirmation that
 * names the consequence while it can still be avoided.
 *
 * The check mirrors DeviceRequirement, and the pieces have to agree with it or the dialog
 * is either missing or crying wolf:
 *
 * - A requirement over no switched-on method does not stand (isEnforceable).
 * - A user who already holds a passkey or an app has met it (hasDeviceFactor).
 * - At the relaxed floor an emailed code counts, where it is on for their role.
 */

/**
 * The factor floor in force, defaulting the way DeviceRequirement::getLevel() does.
 *
 * @param settings the unsaved settings object
 * @return {string}
 */
const level = (settings) => (settings.two_fa_required_level === 'any' ? 'any' : 'device');

/**
 * Whether a device method is switched on at all.
 *
 * `passkey_supported` is read for the same reason PasskeyTwoFaMethod::isSwitchedOn()
 * does: over plain http no passkey can be created, so the switch alone is not the
 * answer.
 *
 * @return {boolean}
 */
function deviceMethodOn(settings, appVars) {
    const passkeyOn = settings.passkey_2fa === 'yes' && !!appVars.passkey_supported;

    return passkeyOn || settings.totp_2fa === 'yes';
}

/**
 * Whether anything that could meet the chosen floor is switched on.
 *
 * @return {boolean}
 */
function enforceable(settings, appVars) {
    if (level(settings) === 'any') {
        return deviceMethodOn(settings, appVars) || settings.email2fa === 'yes';
    }

    return deviceMethodOn(settings, appVars);
}

/**
 * Whether an emailed code would satisfy this user, so nothing changes for them.
 *
 * @return {boolean}
 */
function emailWouldSatisfy(settings, myRoles) {
    if (level(settings) !== 'any' || settings.email2fa !== 'yes') {
        return false;
    }

    const emailRoles = settings.email2fa_roles || [];

    return myRoles.some(role => emailRoles.includes(role));
}

/**
 * Whether saving these settings leaves the current user owing a factor they do not have.
 *
 * @param settings the unsaved settings object
 * @param appVars window.fluentAuthAdmin
 * @return {boolean}
 */
export function selfWillOweFactor(settings, appVars) {
    if (!settings || !appVars || !appVars.me) {
        return false;
    }

    // Already protected, so the requirement is met the moment it is saved.
    if (appVars.me.has_device_factor) {
        return false;
    }

    /*
     * A wp-config.php bypass lifts the requirement for this account - see TwoFaBypass -
     * so nothing happens to them when it is saved. Worth its own line because without it
     * the dialog fires on every save a bypassed administrator makes, including the ones
     * that have nothing to do with 2FA: these screens share one Save button.
     */
    if (appVars.me.two_fa_bypassed) {
        return false;
    }

    const myRoles = appVars.me.roles || [];
    const requiredRoles = settings.totp_required_roles || [];

    if (!myRoles.length || !requiredRoles.length) {
        return false;
    }

    if (!myRoles.some(role => requiredRoles.includes(role))) {
        return false;
    }

    if (!enforceable(settings, appVars)) {
        return false;
    }

    return !emailWouldSatisfy(settings, myRoles);
}
