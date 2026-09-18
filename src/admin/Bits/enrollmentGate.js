import {ElMessageBox} from 'element-plus';

/**
 * What to do when the admin app is refused for owing a second factor.
 *
 * The refusal comes from TotpEnforcementHandler::maybeDenyRest(), and it reaches a
 * session that was signed in before the requirement was switched on - most often the
 * administrator who just switched it on, one request after saving the setting. Until
 * this existed it arrived as a red toast: `$handleError` does not read error codes, so
 * the one refusal on this screen that is not a failure was drawn as one, faded after a
 * few seconds, and left the reader on a screen whose data had silently stopped loading.
 * It also advised signing in again, which is not the shortest way out - a plain reload
 * would have been redirected to the setup page.
 *
 * So it is a modal with one button, and the button goes to the setup page. Blocking is
 * the honest shape: every subsequent request from this session will be refused the same
 * way, so there is nothing else on the screen left to do.
 */
export const ENROLLMENT_REQUIRED = 'fls_2fa_enrollment_required';

/*
 * Several requests can be in flight when the requirement lands - a screen that loads
 * settings and logs together refuses both - and each would otherwise open its own
 * modal on top of the last.
 */
let shown = false;

/*
 * Named `$t` rather than `translate` on purpose. i18n.node.js builds TransStrings.php by
 * scanning src/admin for `$t('...')` calls, so a differently named helper here would
 * leave every string in this file out of the map and shipped as untranslatable English.
 * It is the mixin's lookup, minus the mixin: this runs outside any component.
 */
const $t = (string) => (window.fluentAuthAdmin && window.fluentAuthAdmin.i18n && window.fluentAuthAdmin.i18n[string]) || string;

/**
 * Whether this rejection is the enrollment refusal rather than an ordinary error.
 *
 * Reads the code rather than the message, so it keeps working when the wording changes
 * or the string is translated.
 *
 * @param response the rejected body, which is jQuery's responseJSON - see Bits/Rest.js
 * @return {boolean}
 */
export function isEnrollmentRefusal(response) {
    return !!response && response.code === ENROLLMENT_REQUIRED;
}

/**
 * Where to send them, with a way back to the screen they were on.
 *
 * Exported because two paths lead to the same place and must lead to the same address:
 * this refusal, and the settings screen sending an administrator off to enroll straight
 * after they required it of themselves.
 *
 * @return {string}
 */
export function enrollmentSetupUrl() {
    const base = (window.fluentAuthAdmin && window.fluentAuthAdmin.totp_setup_url) || '';

    if (!base) {
        return '';
    }

    /*
     * The hash carries which admin screen they were reading, and `redirect_to` is
     * validated by wp_validate_redirect() at the other end, so an off-site value lands on
     * the front page rather than off the site.
     */
    const separator = base.indexOf('?') === -1 ? '?' : '&';

    return base + separator + 'redirect_to=' + encodeURIComponent(window.location.href);
}

/**
 * Says what happened and offers the one thing that fixes it.
 *
 * @return {boolean} whether this rejection was handled here
 */
export function handleEnrollmentRefusal(response) {
    if (!isEnrollmentRefusal(response)) {
        return false;
    }

    if (shown) {
        return true;
    }

    shown = true;

    const url = enrollmentSetupUrl();

    ElMessageBox.alert(
        $t('This account now needs a passkey or an authenticator app before it can use the admin area or the site APIs. Setting one up takes about a minute, and brings you straight back here.'),
        $t('Two-factor authentication is required'),
        {
            confirmButtonText: url ? $t('Set it up now') : $t('Reload'),
            /*
             * No close button, no escape, no click-away. Dismissing it would leave the
             * reader on a screen that cannot load anything and no longer says why.
             */
            showClose: false,
            closeOnPressEscape: false,
            closeOnClickModal: false,
            type: 'warning',
            callback: () => {
                window.location.href = url || window.location.href;
            }
        }
    );

    return true;
}

/**
 * Lets a test - or a screen that deliberately re-checks - ask for the modal again.
 *
 * @return {void}
 */
export function resetEnrollmentGate() {
    shown = false;
}
