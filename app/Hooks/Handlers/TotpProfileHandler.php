<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Enrollment for the authenticator app, on the WordPress profile screen.
 *
 * Setting one up is deliberately confined to a user's own profile. An administrator
 * can turn someone else's off - that is the recovery path when a phone is lost - but
 * never on, because doing so would mean pairing an authenticator the account holder
 * does not have and locking them out of their own account.
 *
 * What the user sees is drawn by TwoFaProfileHandler, which puts this method on one card
 * with the others. Everything that decides anything is here: the confirmation that pairs
 * an app is a profile save, and the two operations that weaken an account answer their
 * own requests so that they need no save at all.
 */
class TotpProfileHandler
{
    const NONCE_ACTION = 'fls_totp_profile';

    /**
     * Recovery codes exist only as hashes once stored, so the one moment they can be
     * shown is between being generated and the page that reports it. A profile save
     * redirects, so they are carried across in a short lived transient and deleted the
     * first time they are rendered.
     */
    const NOTICE_TRANSIENT = 'fls_totp_notice_';

    public function register()
    {
        add_action('personal_options_update', [$this, 'handleUpdate']);
        add_action('edit_user_profile_update', [$this, 'handleUpdate']);

        add_action('wp_ajax_fluent_auth_totp_disable', [$this, 'handleDisableRequest']);
        add_action('wp_ajax_fluent_auth_totp_recovery', [$this, 'handleRecoveryRequest']);
    }

    /**
     * @param $userId int
     * @return void
     */
    public function handleUpdate($userId)
    {
        $userId = (int)$userId;

        if (!$userId || !current_user_can('edit_user', $userId)) {
            return;
        }

        if (!wp_verify_nonce(sanitize_text_field(Arr::get($_POST, '_fls_totp_nonce', '')), self::NONCE_ACTION)) {
            return;
        }

        $isSelf = get_current_user_id() === $userId;

        if (Arr::get($_POST, 'fls_totp_disable') === 'yes') {
            TotpTwoFaMethod::disable($userId);
            self::setNotice($userId, 'info', __('The authenticator app has been turned off.', 'fluent-security'));
            return;
        }

        // Everything below pairs a device, which only the account holder can do.
        if (!$isSelf) {
            return;
        }

        /*
         * Any device factor, not this one. Recovery codes belong to the account rather
         * than to the authenticator app - see RecoveryCodes - and gating regeneration on
         * the app left a passkey-only holder with no way to replace a set they never saw.
         * That matters because hasFallback() counts those codes: the account reads as
         * recoverable on the strength of something nobody has.
         *
         * holdsEnrolledDevice() rather than hasDeviceFactor(), so that the lone passkey
         * which is not yet asked for at login still counts as a device worth having a
         * way back in for. See DeviceRequirement.
         */
        if (Arr::get($_POST, 'fls_totp_regenerate_recovery') === 'yes' && DeviceRequirement::holdsEnrolledDevice($userId)) {
            $codes = TotpTwoFaMethod::generateRecoveryCodes($userId);
            self::setNotice($userId, 'codes', __('Your previous recovery codes no longer work. Here is the new set.', 'fluent-security'), $codes);
            return;
        }

        $submitted = sanitize_text_field((string)Arr::get($_POST, 'fls_totp_confirm_code', ''));

        if ($submitted === '' || TotpTwoFaMethod::isEnrolled($userId)) {
            return;
        }

        // The policy may have changed since the form was drawn.
        if (!TotpTwoFaMethod::isAllowedForUser($userId)) {
            return;
        }

        $pending = TotpTwoFaMethod::getPendingSecret($userId);

        if (!$pending) {
            self::setNotice($userId, 'error', __('That setup has expired. Reload this page to start again.', 'fluent-security'));
            return;
        }

        $counter = TotpProvider::verify($pending, $submitted);

        if ($counter === false) {
            self::setNotice($userId, 'error', __('That code did not match. Check your phone clock is set automatically, then try the current code.', 'fluent-security'));
            return;
        }

        /*
         * The confirming step is spent as part of activation, so the very code just
         * typed here cannot be turned around and replayed at the login form.
         */
        TotpTwoFaMethod::activate($userId, $pending, $counter);

        $codes = TotpTwoFaMethod::generateRecoveryCodes($userId);

        self::setNotice($userId, 'codes', __('Your authenticator app is now set up. Save these recovery codes - they are the only way back in if you lose the device, and they are not shown again.', 'fluent-security'), $codes);
    }

    /**
     * Turns the app off, for whoever's profile is open.
     *
     * Not self-only: this is the lost phone path, and an account whose only way back in
     * is a device nobody holds needs somebody else to be able to act. The capability is
     * checked against that specific user rather than against the admin area in general,
     * because it lowers the protection on one account.
     *
     * @return void
     */
    public function handleDisableRequest()
    {
        $userId = $this->authorise();

        if (!TotpTwoFaMethod::isEnrolled($userId)) {
            wp_send_json_error(['message' => __('No authenticator app is set up for this account.', 'fluent-security')], 400);
        }

        TotpTwoFaMethod::disable($userId);

        wp_send_json_success(['message' => __('The authenticator app has been turned off.', 'fluent-security')]);
    }

    /**
     * Issues a fresh set of recovery codes and hands them back once.
     *
     * Self only, unlike turning a factor off: the codes are shown at the moment they are
     * made and never again, so an administrator pressing this for somebody else would
     * be the only person who ever saw that account's way back in.
     *
     * @return void
     */
    public function handleRecoveryRequest()
    {
        $userId = $this->authorise();

        if ($userId !== get_current_user_id()) {
            wp_send_json_error(
                ['message' => __('Recovery codes can only be generated from your own profile.', 'fluent-security')],
                403
            );
        }

        /*
         * Any device factor, not this one - see handleUpdate() above for why a passkey
         * holder has to be able to replace a set of codes they may never have seen.
         * Registered rather than usable, because the account this matters most to is the
         * one holding a lone passkey: the codes are what will make it usable.
         */
        if (!DeviceRequirement::holdsEnrolledDevice($userId)) {
            wp_send_json_error(
                ['message' => __('Set up an authenticator app or a passkey first - recovery codes are the way back in when one of those is lost.', 'fluent-security')],
                400
            );
        }

        wp_send_json_success([
            'codes'   => TotpTwoFaMethod::generateRecoveryCodes($userId),
            'message' => __('Your previous recovery codes no longer work. Here is the new set.', 'fluent-security')
        ]);
    }

    /**
     * Checks the nonce and the capability, and answers whose account is being changed.
     *
     * Exits rather than returning a failure, so no caller can proceed past a refused
     * request by forgetting to check.
     *
     * @return int
     */
    private function authorise()
    {
        check_ajax_referer(self::NONCE_ACTION, '_fls_totp_nonce');

        $userId = (int)Arr::get($_POST, 'user_id');
        $userId = $userId ? $userId : get_current_user_id();

        if (!$userId || !current_user_can('edit_user', $userId)) {
            wp_send_json_error(['message' => __('You cannot change this account.', 'fluent-security')], 403);
        }

        return $userId;
    }

    /**
     * Shared with the front-end setup screen (see TotpSetupPageHandler) rather than
     * duplicated: it is one user being told one thing about their own enrollment, so
     * whichever screen they land on first should be the one that shows it.
     *
     * @param $userId int
     * @param $type string
     * @param $message string
     * @param $codes array
     * @return void
     */
    public static function setNotice($userId, $type, $message, $codes = [])
    {
        set_transient(self::NOTICE_TRANSIENT . $userId, [
            'type'    => $type,
            'message' => $message,
            'codes'   => $codes
        ], 5 * MINUTE_IN_SECONDS);
    }

    /**
     * @param $userId int
     * @return array|false
     */
    public static function pullNotice($userId)
    {
        $notice = get_transient(self::NOTICE_TRANSIENT . $userId);

        if (!$notice) {
            return false;
        }

        delete_transient(self::NOTICE_TRANSIENT . $userId);

        return is_array($notice) ? $notice : false;
    }
}
