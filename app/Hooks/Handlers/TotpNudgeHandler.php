<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Offers an authenticator app to people who could have one and do not.
 *
 * A second factor nobody is told about is a second factor nobody turns on, and the
 * moment after a successful login is the one moment worth asking: they have just proved
 * who they are, they are at a keyboard, and they are not in the middle of anything yet.
 *
 * Asking is all it does. The answer "not now" is taken, and they carry on to wherever
 * they were going - the enforcement handler is what refuses to take no for an answer,
 * and this deliberately steps aside for anyone it covers.
 *
 * It asks after every login. That is a deliberate choice by the site owner rather than
 * the gentlest option available, so `fluent_auth/ask_to_set_up_totp` is here to soften
 * it without patching the plugin - return false and the asking stops.
 */
class TotpNudgeHandler
{
    /**
     * Set when a login happens and spent by the next page load, so the question is asked
     * once per login rather than once per page. It is user meta rather than a session
     * because there is no session to hang it on: the login and the page that follows it
     * are two requests, and the second may be on a different screen entirely.
     */
    const PENDING_META = '_fls_totp_nudge_pending';

    public function register()
    {
        add_action('wp_login', [$this, 'markPending'], 10, 2);

        /*
         * The plugin's own form sets the cookie itself rather than going through
         * wp_signon, so it never reaches `wp_login`. Both are listened for; whichever
         * arrives first sets the same flag, and setting it twice costs nothing.
         */
        add_action('fluent_auth/after_logging_in_user', [$this, 'markPendingForUserId']);

        // The first ordinary page load after that login, wherever it happens to land.
        add_action('template_redirect', [$this, 'maybeAsk']);

        /*
         * Behind the enforcement gate, which registers at 1. Somebody who must have an
         * app should meet the redirect that says so, not this one.
         */
        add_action('admin_init', [$this, 'maybeAsk'], 2);
    }

    /**
     * @param $login string
     * @param $user \WP_User
     * @return void
     */
    public function markPending($login, $user = null)
    {
        if ($user instanceof \WP_User) {
            $this->markPendingForUserId($user->ID);
        }
    }

    /**
     * @param $userId int
     * @return void
     */
    public function markPendingForUserId($userId)
    {
        $userId = (int)$userId;

        if (!$userId) {
            return;
        }

        /*
         * Checked here as well as on the way out. A login is the only moment this can be
         * measured against the user who just performed it, and it keeps the flag off the
         * accounts that will never be asked.
         */
        if (!$this->shouldAsk(get_user_by('ID', $userId))) {
            return;
        }

        update_user_meta($userId, self::PENDING_META, 'yes');
    }

    /**
     * @return void
     */
    public function maybeAsk()
    {
        if (!is_user_logged_in() || $this->isBackgroundRequest()) {
            return;
        }

        $user = wp_get_current_user();

        if (!get_user_meta($user->ID, self::PENDING_META, true)) {
            return;
        }

        /*
         * Spent before the question is asked rather than after it is answered. Whatever
         * happens next - answered, skipped, closed, or a redirect that never arrives -
         * this login has had its one ask.
         */
        delete_user_meta($user->ID, self::PENDING_META);

        // The policy can have changed between the login and this page load.
        if (!$this->shouldAsk($user)) {
            return;
        }

        wp_safe_redirect(TotpSetupPageHandler::getUrl($this->currentUrl(), true));
        exit();
    }

    /**
     * Whether this user is somebody to ask.
     *
     * Public because it is the whole of the decision, and a prompt that interrupts every
     * login is worth being able to ask about directly.
     *
     * @param $user \WP_User|false
     * @return bool
     */
    public function shouldAsk($user)
    {
        if (!$user instanceof \WP_User) {
            return false;
        }

        if (!TotpTwoFaMethod::isAllowedForUser($user)) {
            return false;
        }

        /*
         * Asked as a factor rather than as this one method, so somebody who registered a
         * passkey is left alone. They hold the thing an authenticator app would prove;
         * being offered one after every login reads as the site not noticing.
         *
         * hasDeviceFactor() rather than isSatisfiedBy(), because this is not one of the
         * people the requirement is about. isSatisfiedBy() answers against the configured
         * floor, so at `any` it would count an emailed code - and relaxing a setting that
         * is labelled as being about required roles would silently stop every ordinary
         * user with email codes ever being offered an app.
         */
        if (DeviceRequirement::hasDeviceFactor($user)) {
            return false;
        }

        /*
         * Left to the rule that has no way past it - which is now the enrollment step in
         * the login flow, and the enforcement handler behind it for sessions that predate
         * the policy. Offering "not now" first would only teach them there is one.
         */
        if (DeviceRequirement::isRequiredForUser($user)) {
            return false;
        }

        return (bool)apply_filters('fluent_auth/ask_to_set_up_totp', true, $user);
    }

    /**
     * Where they were going, so answering either way puts them back on their way.
     *
     * Built from the request rather than from a setting because that is the only thing
     * that knows it, and handed to wp_validate_redirect at the other end - a forged host
     * header lands on the front page rather than off the site.
     *
     * @return string
     */
    private function currentUrl()
    {
        $host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
        $uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '';

        if (!$host || !$uri) {
            return home_url();
        }

        return set_url_scheme('http://' . $host . $uri);
    }

    /**
     * Nothing a person is looking at. A redirect sent in reply to one of these breaks
     * the caller instead of reaching anybody.
     *
     * @return bool
     */
    private function isBackgroundRequest()
    {
        if (wp_doing_ajax() || wp_doing_cron()) {
            return true;
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }

        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return true;
        }

        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return true;
        }

        return defined('WP_CLI') && WP_CLI;
    }
}
