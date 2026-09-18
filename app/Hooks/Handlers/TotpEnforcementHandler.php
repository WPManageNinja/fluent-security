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
 * catch. Nor is the requirement applied during that login - see
 * TwoFaHandler::isUnattendedRequest() for why a route with nobody at a keyboard is let
 * through on the password rather than refused, and what `disable_xmlrpc` is for.
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
        add_filter('rest_pre_dispatch', [$this, 'maybeDenyAppPasswordCreation'], 10, 3);
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
            'message' => sprintf(
                /* translators: %s: the URL of the two-factor setup page */
                __('Two-factor authentication must be set up on this account before it can be used. Set one up at %s.', 'fluent-security'),
                TotpSetupPageHandler::getUrl()
            )
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
     * Generating recovery codes is on it for the same reason as registering a passkey,
     * and leaving it off was a complete lockout rather than an inconvenience. A lone
     * passkey does not satisfy the requirement - PasskeyTwoFaMethod::hasFallback() will
     * not have it, because losing that one device would lose the account - and recovery
     * codes are what turn it into a factor that counts. So the user who had done exactly
     * what the screen asked, and needed one more step to finish, was the one user refused
     * that step: registered a passkey, still owed a factor, and the button that would
     * have settled it answered 403. No route in was left that did not involve editing
     * wp-config.php. Reported from 3.0.1 on 2026-09-18.
     *
     * What stays off the list is anything that *weakens* an account: deleting a passkey,
     * renaming one, turning an authenticator app off. A screen reachable by somebody who
     * owes a factor must not be a way to reduce what the account already has - see the
     * same rule in TotpSetupPageHandler.
     *
     * @return array
     */
    private function getPermittedAjaxActions()
    {
        return (array)apply_filters('fluent_auth/enrollment_permitted_ajax_actions', [
            'fluent_auth_passkey_options',
            'fluent_auth_passkey_register',
            'fluent_auth_totp_recovery',
            'heartbeat'
        ]);
    }

    /**
     * Refuses an attempt to mint an application password while a factor is still owed.
     *
     * This used to be a blanket refusal of every cookie-authenticated REST request, and
     * that is now a deliberate, owner-level decision to reverse (2026-09-18). The
     * argument for the blanket version was breadth - a cookie REST session can exercise
     * very nearly everything the account can - and the argument against it is that the
     * population it covers is *only* sessions issued before the policy existed, it
     * empties as those users sign in again, and until it does it breaks ordinary
     * authenticated requests all over the site in ways nobody can diagnose from the
     * symptom. A membership front end making nonce-carrying calls, a plugin's admin
     * screen, core's own `wp/v2/users/me` on the profile page: all 403, all silent.
     *
     * The real enforcement is not here and never was any more - it is
     * EnrollmentTwoFaMethod, before the cookie is issued, where there is no session to
     * contain. What remains here is the backstop for the pre-policy population: they are
     * redirected out of wp-admin pages and refused admin-ajax, and their REST access is
     * left alone.
     *
     * Application passwords stay governed by their own switch rather than by this one,
     * which is the whole of the owner's intent: a site that permits them permits the ones
     * already issued, including any created before two-factor was turned on, and a site
     * that blocks them accepts none at all. `disable_app_login` is that switch, and core
     * honours it for both minting and authenticating - see
     * BasicTasksHandler::maybeDisableAppPassword().
     *
     * What is still refused is *minting a new one* while a factor is owed, and only that.
     * An application password is exempt from every second-factor rule by design, so a
     * user under a requirement who creates one has written themselves a permanent
     * exemption - not used a facility the owner granted, but stepped out of the policy
     * while it was being applied to them. Blocking the one route closes that by
     * construction rather than by relying on `disable_app_login`, which defaults to off
     * and is deliberately left out of "apply recommended" because it breaks integrations.
     *
     * Hooked on `rest_pre_dispatch` rather than `rest_authentication_errors` because this
     * decision needs the route, and that is the earliest filter handed the
     * WP_REST_Request - reading it out of REQUEST_URI instead would mean a security gate
     * resting on string parsing.
     *
     * @param $result mixed null to carry on, anything else short-circuits the dispatch
     * @param $server \WP_REST_Server
     * @param $request \WP_REST_Request
     * @return mixed
     */
    public function maybeDenyAppPasswordCreation($result, $server = null, $request = null)
    {
        // Somebody else has already answered this request.
        if ($result !== null || !$request instanceof \WP_REST_Request) {
            return $result;
        }

        if (!in_array(strtoupper($request->get_method()), ['POST', 'PUT', 'PATCH'], true)) {
            return $result;
        }

        /*
         * Matched on the route the server resolved, so `?rest_route=` and a pretty
         * permalink are the same string by the time it gets here. Core registers these
         * under /wp/v2/users/<id|me>/application-passwords plus /<uuid> beneath it.
         */
        if (!preg_match('#/application-passwords(/|$)#', (string)$request->get_route())) {
            return $result;
        }

        if (!is_user_logged_in() || !$this->owesDeviceFactor(wp_get_current_user())) {
            return $result;
        }

        if (!apply_filters('fluent_auth/enforce_enrollment_on_rest', true, wp_get_current_user())) {
            return $result;
        }

        /*
         * The code is the contract, not the sentence: the admin app keys on
         * `fls_2fa_enrollment_required` to draw a dialog with a way out rather than the
         * red toast every other rejection gets - see Bits/enrollmentGate.js.
         */
        return new \WP_Error(
            'fls_2fa_enrollment_required',
            sprintf(
                /* translators: %s: the URL of the two-factor setup page */
                __('Set up two-factor authentication before creating an application password. You can do that at %s.', 'fluent-security'),
                TotpSetupPageHandler::getUrl()
            ),
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
                <?php
                /*
                 * "A second factor", not "an authenticator app". The requirement is read
                 * as a factor - see DeviceRequirement - so naming one method was wrong
                 * wherever the other was the one switched on, and it was wrong on the
                 * screen most likely to be read by somebody the app is not available to.
                 */
                esc_html_e('Set up a passkey or an authenticator app below to continue. Until you do, this account cannot use the admin area or the site APIs.', 'fluent-security');
                ?>
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
