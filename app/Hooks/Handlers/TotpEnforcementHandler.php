<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Services\TwoFa\DeviceRequirement;

/**
 * The backstop behind the enrollment step in the login flow.
 *
 * This class used to be the whole of the rule, and it gated `admin_init` deliberately:
 * enrolling mid-login means pairing a factor for whoever just typed the password, so an
 * attacker holding only that could register their own authenticator. Waiting until
 * after login avoided it.
 *
 * That trade has been reversed, knowingly. What it bought was small - an attacker who
 * has the password is already inside for every purpose except this one - and what it
 * cost was the enforcement being decorative. A gate on `admin_init` runs after the auth
 * cookie has been issued, so the user it was holding back already had a working
 * session: it hid the dashboard from them while REST, XML-RPC and admin-ajax stayed
 * open, to this plugin and to every other plugin installed. A policy that stops
 * somebody reading wp-admin while leaving them the whole REST API is not a policy.
 *
 * So the rule now lives in EnrollmentTwoFaMethod, before the cookie, where there is no
 * session to leave open. What remains here is the population that step cannot reach:
 * users who were already signed in when the requirement was switched on. They hold a
 * cookie that predates the policy, and until they next sign in this is the only thing
 * standing in front of them - which is why it refuses the two API surfaces that cookie
 * still opens, REST and admin-ajax, rather than only the one a person looks at.
 *
 * XML-RPC is not among them, and deliberately: it authenticates with a username and
 * password on every call and carries no cookie, so there is no pre-existing session to
 * catch. That route is refused during the login itself, by
 * TwoFaHandler::maybeDenyHeadlessLogin(), which is where it belongs.
 *
 * The requirement is read as a factor, not a product: a user who registered a passkey
 * has met it, and used to be marched off to set up an authenticator app anyway.
 */
class TotpEnforcementHandler
{
    public function register()
    {
        add_action('admin_init', [$this, 'maybeForceEnrollment'], 1);
        add_action('admin_notices', [$this, 'renderNotice']);

        /*
         * The surfaces the redirect above can never cover. A cookie issued before the
         * policy existed authenticates these exactly as it always did, and answering
         * them with a redirect breaks the caller instead of reaching anybody - so they
         * are refused outright and told why.
         *
         * admin-ajax.php fires `admin_init` of its own (wp-admin/admin-ajax.php) before
         * dispatching, which is why this can ride the same hook at a lower priority
         * rather than needing one of its own.
         */
        add_action('admin_init', [$this, 'maybeDenyAjax'], 0);
        add_filter('rest_authentication_errors', [$this, 'maybeDenyRest'], 101);
    }

    /**
     * Refuses an admin-ajax call made with a session that owes a device factor.
     *
     * Blunt on purpose. There is no way to ask an arbitrary `wp_ajax_` handler how much
     * authority it exercises, and the population this applies to is both small and
     * temporary - it empties as those users sign in again - so the safe reading is that
     * a session which may not use wp-admin may not drive wp-admin's ajax endpoints
     * either. `fluent_auth/enrollment_permitted_ajax_actions` is the way out for a site
     * whose front end needs a particular action kept open.
     *
     * @return void
     */
    public function maybeDenyAjax()
    {
        if (!wp_doing_ajax() || !is_user_logged_in()) {
            return;
        }

        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';

        if (in_array($action, $this->getPermittedAjaxActions(), true)) {
            return;
        }

        if (!$this->owesDeviceFactor(wp_get_current_user())) {
            return;
        }

        wp_send_json([
            'message' => __('Two-factor authentication must be set up on this account before it can be used.', 'fluent-security')
        ], 403);
    }

    /**
     * The ajax actions that stay open to somebody who still owes a factor.
     *
     * Registering a passkey is on the list because it is one of the two ways to satisfy
     * the very requirement being enforced, and it is driven entirely over ajax from the
     * profile screen - closing it would leave a user told to set up a second factor and
     * refused the means to do it. The heartbeat is on it because refusing that produces
     * console noise on every page and protects nothing.
     *
     * @return array
     */
    private function getPermittedAjaxActions()
    {
        return (array)apply_filters('fluent_auth/enrollment_permitted_ajax_actions', [
            'fluent_auth_passkey_options',
            'fluent_auth_passkey_register',
            'heartbeat'
        ]);
    }

    /**
     * Refuses a REST request made with a session that owes a device factor.
     *
     * Runs at 101, *after* core's rest_cookie_check_errors() at 100, and the ordering is
     * the whole correctness of this function. Core treats a REST request that carries a
     * login cookie but no `_wpnonce` / `X-WP-Nonce` as anonymous: it calls
     * wp_set_current_user(0) and returns true. Ahead of that, is_user_logged_in() still
     * answers yes, so an ordinary nonce-less fetch against a *public* endpoint - the kind
     * a theme makes on the front end - would come back 403 for this user and nobody else.
     * Behind it, the current user is already zero for exactly those requests, so asking
     * the question here asks it of a session core has agreed is really being used.
     *
     * An error raised by something else is handed back untouched rather than replaced,
     * and an application password is left alone to stay consistent with
     * TwoFaHandler::maybeDenyHeadlessLogin(), which exempts them and defers to the
     * plugin's own `disable_app_login` switch instead.
     *
     * @param $result \WP_Error|null|true
     * @return \WP_Error|null|true
     */
    public function maybeDenyRest($result)
    {
        // Somebody else's refusal, and theirs to explain.
        if (is_wp_error($result)) {
            return $result;
        }

        if (function_exists('rest_get_authenticated_app_password') && rest_get_authenticated_app_password()) {
            return $result;
        }

        if (!is_user_logged_in() || !$this->owesDeviceFactor(wp_get_current_user())) {
            return $result;
        }

        return new \WP_Error(
            'fls_2fa_enrollment_required',
            __('Two-factor authentication must be set up on this account before it can be used. Please sign in again to finish.', 'fluent-security'),
            ['status' => 403]
        );
    }

    /**
     * @param $user \WP_User|false
     * @return bool
     */
    private function owesDeviceFactor($user)
    {
        return $user instanceof \WP_User && DeviceRequirement::isOwedBy($user);
    }

    /**
     * @return void
     */
    public function maybeForceEnrollment()
    {
        if (!$this->needsEnrollment()) {
            return;
        }

        // Already where they need to be; redirecting again would be a loop.
        if ($this->isEnrollmentScreen()) {
            return;
        }

        /*
         * Sent to the standalone screen rather than to their profile. The profile screen
         * is inside the admin area, which is exactly what this rule is holding shut - and
         * on a site that keeps a role out of wp-admin altogether, being sent there means
         * being bounced straight back out again with nothing set up.
         *
         * They came here trying to use the admin area, so that is where Continue returns
         * them to once they are done.
         */
        wp_safe_redirect(TotpSetupPageHandler::getUrl(admin_url()));
        exit();
    }

    /**
     * @return void
     */
    public function renderNotice()
    {
        if (!$this->needsEnrollment() || !$this->isEnrollmentScreen()) {
            return;
        }

        ?>
        <div class="notice notice-warning">
            <p>
                <strong><?php esc_html_e('Two-factor authentication is required for your account.', 'fluent-security'); ?></strong>
                <?php esc_html_e('Set up an authenticator app below to continue. Until you do, this account cannot use the admin area or the site APIs.', 'fluent-security'); ?>
            </p>
        </div>
        <?php
    }

    /**
     * Whether this request belongs to someone who owes an authenticator app.
     *
     * Public because it is the whole of the decision - the redirect around it is two
     * lines - and a rule that can lock an administrator out of their own site should be
     * something tests can ask about directly.
     *
     * @return bool
     */
    public function needsEnrollment()
    {
        if (!is_user_logged_in()) {
            return false;
        }

        /*
         * Only ordinary page loads. A redirect sent in reply to an ajax call, a cron
         * run or a REST request breaks the caller rather than reaching anybody, and
         * these are not how someone browses the admin area anyway.
         */
        if (wp_doing_ajax() || wp_doing_cron() || $this->isRestRequest()) {
            return false;
        }

        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return false;
        }

        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }

        return $this->owesDeviceFactor(wp_get_current_user());
    }

    /**
     * The profile screen still carries a setup form and still posts back to itself, so
     * somebody who went there under their own steam is left to finish there rather than
     * being pulled off the page mid-enrollment.
     *
     * The standalone screen needs no exemption: it lives on wp-login.php, where
     * admin_init never runs.
     *
     * @return bool
     */
    private function isEnrollmentScreen()
    {
        global $pagenow;

        return $pagenow === 'profile.php';
    }

    /**
     * @return bool
     */
    private function isRestRequest()
    {
        return (defined('REST_REQUEST') && REST_REQUEST)
            || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST);
    }
}
