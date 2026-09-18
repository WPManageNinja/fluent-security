<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Services\TwoFa\RivalStandDown;
use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\BaseTwoFaMethod;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaBypass;
use FluentAuth\App\Services\TwoFa\TwoFaService;

/**
 * Owns the login flow around a second factor.
 *
 * The proof itself belongs to a method (see BaseTwoFaMethod) - this class only handles
 * what every method needs identically: raising the pending row, carrying the redirect
 * intent and the remember-me flag across the challenge, capping guesses, reporting
 * failures to the attempt limit and completing the sign in.
 */
class TwoFaHandler
{
    /**
     * How many times a single issued challenge may be guessed before it is burned.
     * Matches AuthService::verifyTokenHash so both flows behave the same way.
     */
    const MAX_VERIFY_ATTEMPTS = 5;

    /**
     * How long a raised challenge stays answerable, in seconds.
     */
    const PENDING_TIMEOUT = 600;

    /**
     * Codes issued because email 2FA is switched on for the user's role.
     *
     * @deprecated Use EmailTwoFaMethod::getKey(). Kept because it is a published value.
     */
    const USE_TYPE = 'email_2_fa';

    /**
     * Codes issued because the account itself is under attack. Recorded separately so
     * the code stays usable even where email 2FA is not otherwise enabled.
     *
     * @deprecated Use EmailTwoFaMethod::getChallengeKey().
     */
    const CHALLENGE_USE_TYPE = '2fa_challenge';

    private $challengeCache = [];

    /**
     * True only while verifyChallenge() completes a sign in whose proof has just been
     * checked. Static because the wp_signon() it runs goes back through the `authenticate`
     * chain, where every registered instance of this class would otherwise see a login
     * that still looks like it owes a second factor.
     */
    private static $completingChallenge = false;

    /**
     * Where a challenge raised outside the login form waits for the browser to come
     * back - see maybeResumePendingChallenge().
     */
    const PENDING_COOKIE = 'fls_2fa_pending';

    /**
     * Users refused an auth cookie in this request, by id. Static for the same reason as
     * $completingChallenge: LoginSecurityHandler asks about it from another instance.
     */
    private static $withheldUsers = [];

    /**
     * Users this request let past a headless login without a challenge, by id.
     * Read by maybeWithholdAuthCookies() so the cookie follows the decision.
     */
    private static $headlessPassedUsers = [];

    /**
     * The user core is about to issue cookies for, caught from `set_auth_cookie` because
     * `send_auth_cookies` only started naming them in WordPress 6.2.
     */
    private $cookieUserId = null;

    /**
     * Whoever this request's own cookie proved to be, recorded the moment core validated
     * it. Read later rather than re-validated later: by the time a cookie is re-issued,
     * the one that got them here may already be dead - a password change invalidates its
     * hash, the recovery sweep destroys its session - and re-checking it then would sign
     * out the very person doing the renewing.
     */
    private static $cookieAuthenticatedUserId = 0;

    /**
     * Whether any auth cookie has been minted in this request. Once one has, nothing
     * validated afterwards can be trusted to describe who *arrived*: a plugin that
     * writes its freshly issued cookie into $_COOKIE (WooCommerce's Store API does, so
     * nonces work straight after sign in) would otherwise have it vouch for itself.
     */
    private static $cookieMinted = false;

    /**
     * Whether an application password authenticated this request. Those exist to skip
     * interactive factors, and the plugin has its own switch for refusing them.
     */
    private static $appPasswordAuthenticated = false;

    /**
     * @param $user \WP_User
     * @return bool
     */
    private function isChallengeRequired($user)
    {
        if (!$user instanceof \WP_User) {
            return false;
        }

        if (!isset($this->challengeCache[$user->ID])) {
            $this->challengeCache[$user->ID] = (bool)apply_filters('fluent_auth/2fa_challenge_required', false, $user);
        }

        return $this->challengeCache[$user->ID];
    }

    /**
     * The use_type to record for a challenge about to be raised.
     *
     * A row marked with the challenge key authorises itself at verify time, so it keeps
     * working even if the attack has died down or the method was never enabled for the
     * role. That only has to be recorded for a method that distinguishes the two - the
     * base implementation returns its own key for both - so the expensive question of
     * whether the account is under attack is asked only where the answer is recorded.
     *
     * @param $user \WP_User
     * @param $method \FluentAuth\App\Services\TwoFa\BaseTwoFaMethod
     * @return string
     */
    private function resolveUseType($user, $method)
    {
        if ($method->getChallengeKey() === $method->getKey()) {
            return $method->getKey();
        }

        return $this->isChallengeRequired($user) ? $method->getChallengeKey() : $method->getKey();
    }

    public function register()
    {
        add_action('fluent_auth/login_attempts_checked', [$this, 'maybe2FaRedirect'], 1, 1);

        /*
         * After LoginSecurityHandler (999), which is what fires the action above. Where
         * that action cannot show a challenge it does nothing, and this is what turns
         * "nothing" into a refusal - see maybeDenyHeadlessLogin().
         */
        add_filter('authenticate', [$this, 'maybeDenyHeadlessLogin'], 1000, 1);

        /*
         * The last line. Everything above works through the login chain, and a plugin
         * that sets the auth cookie itself never enters it - see maybeWithholdAuthCookies().
         */
        add_action('auth_cookie_valid', [$this, 'rememberAuthenticatedUser'], 10, 2);
        add_action('application_password_did_authenticate', [$this, 'rememberAppPasswordAuth']);
        add_action('set_auth_cookie', [$this, 'rememberCookieUser'], 10, 4);
        add_filter('send_auth_cookies', [$this, 'maybeWithholdAuthCookies'], 999, 4);

        // A challenge raised where no form could be shown is picked up on the next page.
        add_action('template_redirect', [$this, 'maybeResumePendingChallenge'], 1);
        add_action('login_init', [$this, 'maybeResumePendingChallenge'], 1);

        add_action('login_form_' . TwoFaService::LOGIN_ACTION, [$this, 'render2FaForm'], 1);
        add_action('login_form_' . TwoFaService::SWITCH_ACTION, [$this, 'switchMethod'], 1);
        add_action('wp_ajax_nopriv_' . TwoFaService::AJAX_ACTION, [$this, 'verifyChallenge']);

        // Already signed in: nothing to verify, just tell the form where to go.
        add_action('wp_ajax_' . TwoFaService::AJAX_ACTION, [$this, 'reportChallengeRedirect']);
    }

    /**
     * @return void
     */
    public function reportChallengeRedirect()
    {
        $hash = sanitize_text_field(Arr::get($_REQUEST, 'login_hash'));

        $logHash = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $hash)
            ->whereIn('use_type', TwoFaService::getAllUseTypes())
            ->orderBy('id', 'DESC')
            ->first();

        $user = get_user_by('ID', get_current_user_id());
        $redirectTo = admin_url();

        if ($logHash && $logHash->redirect_intend) {
            $redirectTo = $logHash->redirect_intend;
            $redirectTo = apply_filters('login_redirect', $redirectTo, $logHash->redirect_intend, $user);
        }

        wp_send_json([
            'redirect' => $redirectTo
        ]);
    }

    public function render2FaForm()
    {
        if (Arr::get($_GET, 'fls_2fa') !== TwoFaService::CHALLENGE_MARKER) {
            return;
        }

        /*
         * The pending row is the authority on whether a challenge is outstanding. A
         * challenge can be raised on a site where the method is otherwise off, so
         * re-checking the settings here would dead end that login.
         */
        $logHash = $this->getPendingRow(Arr::get($_REQUEST, 'login_hash'));

        if (!$logHash) {
            return false;
        }

        $method = TwoFaService::getMethodByUseType($logHash->use_type);

        if (!$method) {
            return false;
        }

        login_header(__('Provide Login Code', 'fluent-security'), '', null);
        do_action('fls_load_login_helper');
        echo $method->renderForm($_REQUEST); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped

        /*
         * The way out, for somebody who cannot answer what is above. Rendered for every
         * method rather than inside any of them: a lost phone, an authenticator that was
         * never moved to the new one and a browser that will not do WebAuthn are all the
         * same dead end, and each method would otherwise have to grow its own copy.
         */
        echo TwoFaBypass::renderHelp(get_user_by('ID', $logHash->user_id)); // PHPCS:Ignore WordPress.Security.EscapeOutput.OutputNotEscaped

        login_footer();
        exit();
    }

    /**
     * Trades an outstanding challenge for one the user can actually answer.
     *
     * Reached from a link on the challenge form itself. There is no nonce because there
     * is no session yet to tie one to - the pending hash is the only credential this
     * screen has, and it is the same one that authorises answering the challenge in the
     * first place. Whoever holds it can already attempt the login.
     *
     * The old row is spent before the new one is raised, so a switch cannot be used to
     * keep several live challenges open for one account and answer whichever lands.
     *
     * @return void
     */
    public function switchMethod()
    {
        $logHash = $this->getPendingRow(Arr::get($_REQUEST, 'login_hash'));

        if (!$logHash) {
            wp_safe_redirect(wp_login_url());
            exit();
        }

        $user = get_user_by('ID', $logHash->user_id);
        $current = TwoFaService::getMethodByUseType($logHash->use_type);
        $alternative = ($user && $current) ? TwoFaService::getAlternativeMethod($user, $current) : null;

        if (!$alternative) {
            wp_safe_redirect(TwoFaService::getChallengeUrl($logHash->login_hash));
            exit();
        }

        $this->invalidate2FaCode($logHash);

        $redirectTo = $this->sendAndGet2FaConfirmFormUrl(
            $user,
            'url',
            $logHash->redirect_intend,
            $alternative
        );

        wp_safe_redirect($redirectTo ? $redirectTo : wp_login_url());
        exit();
    }

    public function maybe2FaRedirect($user)
    {
        if (self::$completingChallenge) {
            return false;
        }

        /*
         * Nobody is waiting on this one - see isUnattendedRequest(). Checked ahead of
         * cannotShowChallenge() because WP-CLI and cron are not in that list: a sign in
         * driven from either would otherwise mail a code and then run wp_safe_redirect()
         * and exit() inside a process with no browser to redirect.
         */
        if ($this->isUnattendedRequest()) {
            return false;
        }

        // Nowhere to send a form. maybeDenyHeadlessLogin() decides what happens instead.
        if ($this->cannotShowChallenge()) {
            return false;
        }

        $return = $this->sendAndGet2FaConfirmFormUrl($user, 'both');

        if (!$return) {
            return false;
        }

        if (wp_doing_ajax()) {
            /*
             * challenge_url alongside the markup, for a caller that would rather send the
             * browser to the full page than mount the form. A host that opted in through
             * `fluent_auth/can_render_2fa_inline` may still find our script absent - it is
             * only enqueued where something asked for it - and this is what it falls back
             * to rather than showing a form nothing has wired.
             */
            wp_send_json([
                'load_2fa'      => 'yes',
                'two_fa_form'   => $this->get2FaFormHtml($return),
                'challenge_url' => $return['redirect_to']
            ]);
        }

        wp_safe_redirect($return['redirect_to']);
        exit();
    }

    /**
     * Raises a second factor challenge for this user, if one is still owed.
     *
     * @param $user \WP_User
     * @param $return string 'url' or 'both'
     * @param $redirectIntend string|null explicit intent for callers that do not carry
     *                                    it in $_REQUEST, such as social login
     * @return array|string|false
     */
    public function sendAndGet2FaConfirmFormUrl($user, $return = 'url', $redirectIntend = null, $method = null)
    {
        /*
         * Passed unresolved: whether the account is under attack costs two queries over
         * the auth log, and for the common login - a user with a method already enrolled
         * - it cannot change which method is asked for. See getRequiredMethod().
         *
         * A method given by the caller is one switchMethod() has already established the
         * user can answer, so the dispatcher is not asked again - it would only return
         * the method being switched away from.
         */
        if (!$method instanceof BaseTwoFaMethod) {
            $method = TwoFaService::getRequiredMethod($user, null, function () use ($user) {
                return $this->isChallengeRequired($user);
            });
        }

        if (!$method) {
            return false;
        }

        $string = $user->ID . '-' . wp_generate_uuid4() . mt_rand(1, 99999999);
        $hash = wp_hash_password($string);
        $hash = sanitize_title($hash, '', 'display');
        $hash .= $user->ID . '-' . time();

        if ($redirectIntend === null) {
            $redirectIntend = $this->resolveRedirectIntent();
        }

        if (isset($_REQUEST['rememberme'])) {
            $hash .= '-auth';
        }

        $challenge = $method->prepareChallenge($user);

        $data = array(
            'login_hash'      => $hash,
            'user_id'         => $user->ID,
            'status'          => 'issued',
            'ip_address'      => Helper::getIp(),
            'redirect_intend' => $redirectIntend,
            'use_type'        => $this->resolveUseType($user, $method),
            'valid_till'      => date('Y-m-d H:i:s', current_time('timestamp') + self::PENDING_TIMEOUT),
            'created_at'      => current_time('mysql'),
            'updated_at'      => current_time('mysql')
        );

        $data = array_merge($data, (array)Arr::get($challenge, 'columns', []));

        flsDb()->table('fls_login_hashes')
            ->insert($data);

        $method->dispatchChallenge($user, $challenge, [
            'login_hash'  => $hash,
            'redirect_to' => $redirectIntend,
            'row'         => $data
        ]);

        $redirectTo = TwoFaService::getChallengeUrl($hash);

        if ($return === 'url') {
            return $redirectTo;
        }

        return [
            'redirect_to' => $redirectTo,
            'login_hash'  => $hash
        ];
    }

    public function verifyChallenge()
    {
        $hash = sanitize_text_field(Arr::get($_REQUEST, 'login_hash'));

        if (!$hash) {
            wp_send_json([
                'message' => __('Please provide a valid login code', 'fluent-security')
            ], 422);
        }

        $logHash = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $hash)
            ->whereIn('use_type', TwoFaService::getAllUseTypes())
            ->orderBy('id', 'DESC')
            ->first();

        if (!$logHash) {
            wp_send_json([
                'message' => __('Your provided code or url is not valid', 'fluent-security')
            ], 422);
        }

        $method = TwoFaService::getMethodByUseType($logHash->use_type);
        $user = get_user_by('ID', $logHash->user_id);

        /*
         * Every one of these has to be settled BEFORE the proof is compared. Checking
         * them afterwards (as this used to) means the attempt cap only ever applies to
         * a code that already matched, so a wrong code could be retried indefinitely.
         */
        if (!$user || !$method || $logHash->status != 'issued' || strtotime($logHash->created_at) < current_time('timestamp') - self::PENDING_TIMEOUT) {
            wp_send_json([
                'message' => __('Sorry, your login code has been expired. Please try to login again', 'fluent-security')
            ], 422);
        }

        if ($logHash->used_count >= self::MAX_VERIFY_ATTEMPTS) {
            $this->invalidate2FaCode($logHash);

            wp_send_json([
                'message' => __('Too many invalid attempts for this login code. Please try to login again', 'fluent-security')
            ], 422);
        }

        /*
         * A challenge authorises itself: it was raised precisely because the account was
         * under attack, so it has to keep working even if the attack has since died down
         * or the method is not enabled for this role at all.
         */
        if ($logHash->use_type !== $method->getChallengeKey() && !$method->isAvailableForUser($user)) {
            wp_send_json([
                'message' => __('Sorry, You can not use this verification method', 'fluent-security')
            ], 422);
        }

        $verified = $method->verifyProof($user, $logHash, $_REQUEST);

        if (is_wp_error($verified)) {
            wp_send_json([
                'message' => $verified->get_error_message()
            ], 422);
        }

        if (!$verified) {
            $this->recordFailedAttempt($logHash, $user, $method);

            wp_send_json([
                'message' => __('Your provided code is not valid. Please try again', 'fluent-security')
            ], 422);
        }

        // They already produced the proof: no further challenge, and no attempt limit.
        self::$completingChallenge = true;
        Helper::setTokenVerifiedLogin(true);

        /*
         * Before wp_signon(), because that is what fires `wp_login` and writes the
         * success row. Set afterwards, as it used to be, every login completed with a
         * code was recorded as a plain form login.
         */
        Helper::setLoginMedia($method->getLoginMedia());

        add_filter('authenticate', array($this, 'allowProgrammaticLogin'), 10, 3);    // hook in earlier than other callbacks to short-circuit them

        /*
         * The one moment another plugin's second factor has to stand down.
         *
         * wp_signon() fires `wp_login`, and a rival listening there throws this session away
         * and renders its own challenge into the middle of this request - which is the loop
         * described in RivalTwoFa. Several of them publish a filter for exactly this,
         * so where one exists the loop simply does not happen.
         *
         * Safe here and nowhere else: the user has just produced a second factor, so what is
         * being stood down is a duplicate rather than a factor. Every login that did not come
         * through this method - including one where our own second factor did not apply - is
         * untouched, so a site whose policy is really being enforced by the other plugin goes
         * on being enforced by it.
         *
         * finally, because a stand-down left attached would be this plugin quietly switching
         * somebody else's second factor off for the rest of the request.
         */
        RivalStandDown::standDown();

        try {
            $user = wp_signon(array(
                    'user_login'    => $user->user_login,
                    'user_password' => '',
                    'remember'      => (bool)strpos($logHash->login_hash, '-auth')
                )
            );
        } finally {
            RivalStandDown::resume();
        }

        remove_filter('authenticate', array($this, 'allowProgrammaticLogin'), 10);

        Helper::setTokenVerifiedLogin(false);
        self::$completingChallenge = false;

        if ($user instanceof \WP_User) {
            wp_set_current_user($user->ID, $user->user_login);
            if (is_user_logged_in()) {
                flsDb()->table('fls_login_hashes')
                    ->where('id', $logHash->id)
                    ->update([
                        'status'             => 'used',
                        'success_ip_address' => Helper::getIp()
                    ]);

                $redirectTo = $logHash->redirect_intend;
                if (!$redirectTo) {
                    $redirectTo = admin_url();
                }

                $this->clearPendingCookie();

                $redirectTo = apply_filters('login_redirect', $redirectTo, $logHash->redirect_intend, $user);

                /*
                 * The method gets the last word on the reply. Almost all of them want
                 * only the redirect; enrollment has recovery codes to hand over, and
                 * they are shown once or never.
                 */
                wp_send_json($method->getSuccessResponse([
                    'redirect' => $redirectTo
                ], $user, $logHash));
            }
        }

        wp_send_json([
            'message' => __('There has an error when log you in. Please try to login again', 'fluent-security')
        ], 422);
    }

    public function allowProgrammaticLogin($user, $username, $password)
    {
        return get_user_by('login', $username);
    }

    /**
     * Refuses a login that still owes a second factor where no challenge can be shown.
     *
     * The request used to be left alone here, on the theory that interfering with
     * another plugin's AJAX handler would break it. It did leave it alone - and with it
     * every second factor the account had, because maybe2FaRedirect() is the only thing
     * standing between a correct password and the auth cookie. A theme's popup login
     * form, or a magic link opened through admin-ajax.php, was a complete bypass of the
     * emailed code, the authenticator app and the under-attack challenge.
     *
     * A WP_Error is the one answer every caller of wp_signon() already knows how to show.
     * Accounts that owe nothing are untouched, so a login form that never met a second
     * factor before will not meet one now.
     *
     * @param $user \WP_User|\WP_Error|null
     * @return \WP_User|\WP_Error|null
     */
    public function maybeDenyHeadlessLogin($user)
    {
        if (self::$completingChallenge || !$user instanceof \WP_User) {
            return $user;
        }

        if (!$this->cannotShowChallenge()) {
            return $user;
        }

        /*
         * Nobody to refuse and nobody to mail - see isUnattendedRequest(). The login
         * proceeds on the password alone, which is the deliberate trade documented there.
         */
        if ($this->isUnattendedRequest()) {
            return $user;
        }

        /*
         * Not every wp_authenticate() is a sign in. A "confirm your password" dialog
         * re-checks the password of whoever is already here, and there is nothing to
         * gain from challenging someone who has already answered.
         */
        if ($this->arrivedSignedInAs($user->ID)) {
            return $user;
        }

        /*
         * An application password over XML-RPC comes through this chain too. It is the
         * one credential built to skip interactive factors; whether a site allows them
         * at all is `disable_app_login`, not this.
         */
        if (self::$appPasswordAuthenticated) {
            return $user;
        }

        $method = TwoFaService::getRequiredMethod($user, null, function () use ($user) {
            return $this->isChallengeRequired($user);
        });

        if (!$method) {
            return $user;
        }

        if ($this->headlessLoginMayPass($user, $method)) {
            return $user;
        }

        /*
         * Refused, and nothing raised behind it.
         *
         * A challenge only means something to a caller that can come back for it, and a
         * REST client posting credentials to a route of its own cannot: no form, no
         * pending cookie, no way to spend the code. Raising one anyway wrote a row nobody
         * could answer and mailed a code to somebody who had not asked for it - on a
         * client polling with the right password, one every few minutes.
         *
         * The refusal itself stands. Application passwords are the way in for a client
         * that needs one, and they are exempt above.
         */
        if (!$this->canResumeInBrowser()) {
            return new \WP_Error(
                'fls_2fa_required',
                __('This account needs a second factor, which cannot be completed over the REST API. Sign in through the site\'s login page, or use an application password.', 'fluent-security')
            );
        }

        /*
         * Refused, but not stranded. The challenge is raised exactly as the login form
         * would have raised it, and the error carries the link to answer it - most login
         * forms print the message they get back, so the user can carry on from there. A
         * form that reloads the page instead is caught by the cookie.
         */
        $raised = $this->sendAndGet2FaConfirmFormUrl($user, 'both');

        if (!$raised) {
            return $user;
        }

        $this->setPendingCookie($raised['login_hash']);

        return new \WP_Error(
            'fls_2fa_required',
            $this->getHandoffMessage($method, $raised['redirect_to']),
            ['challenge_url' => $raised['redirect_to']]
        );
    }

    /**
     * Whether a login from somebody else's form is let through rather than refused.
     *
     * A form that cannot show a challenge leaves only two outcomes, and both cost
     * something: refuse the login, and an ordinary visitor on a third-party form meets an
     * error asking them to finish somewhere else; allow it, and a factor that would have
     * been asked for is not asked for.
     *
     * The line drawn here is what the *user* has done and how much they can do, not what
     * the form is:
     *
     * - Only an account that cannot publish is let through. `publish_posts` is the same
     *   line Helper::getLowLevelRoles() already draws for the admin-area settings, and it
     *   is what separates a subscriber or a customer from anybody who can change the
     *   site. It matters because the shipped default has email codes on for
     *   administrators, editors and authors and nobody in the required list - so a rule
     *   that read only the required list would hand every default install's
     *   administrator a way past their own second factor.
     *
     * - Somebody who set up an authenticator app or registered a passkey is never let
     *   through. They opted into a second step; the form they happened to use is not a
     *   reason to drop it. holdsEnrolledDevice() rather than hasDeviceFactor() on
     *   purpose - a lone passkey is not asked for at sign-in, but it is still a device
     *   this account chose to register.
     * - Nor is anybody the site *requires* to hold one. That setting is the site saying
     *   the account may not be reached without a second factor, and a login path is not
     *   an exception to it.
     * - Nor is an account under attack. getRequiredMethod() only hands back a method
     *   that is not available to the user when the repeated-failure fallback fired, so
     *   an unavailable method here means the challenge is the escalation rather than the
     *   standing policy - the one case where challenging somebody who enrolled in
     *   nothing is the whole point.
     *
     * What is left is a visitor with no second factor of their own, on a site that does
     * not require one of them, who would have been shown an emailed code. That code is
     * still asked for on every form the plugin can draw a challenge on; this is only
     * about the forms where the alternative is an error message.
     *
     * @param $user \WP_User
     * @param $method \FluentAuth\App\Services\TwoFa\BaseTwoFaMethod
     * @return bool
     */
    /**
     * The capabilities an account may hold and still be waved through.
     *
     * An allow list, and it has to be. The first version of this named the capabilities
     * that disqualify somebody, which is a list you cannot finish: `activate_plugins`,
     * `delete_users`, `unfiltered_html`, `switch_themes`, `update_core`, `import`, and
     * whatever a membership plugin registered this morning were all missing from it, so a
     * subscriber holding any one of them was let past. Naming what is harmless instead
     * fails the safe way - an unrecognised capability refuses the pass rather than
     * granting it, and the site meets the handoff message it used to.
     *
     * `read` and `level_0` are what an ordinary member has. A site whose customers hold
     * some inert capability of its own adds it here.
     *
     * @return array
     */
    private static function harmlessCapabilities()
    {
        return apply_filters('fluent_auth/headless_harmless_capabilities', [
            'read',
            'level_0'
        ]);
    }

    /**
     * The capabilities asked through user_can() rather than read from the stored set.
     *
     * The walk below reads `allcaps`, which is what the roles and the user row grant. A
     * `user_has_cap` filter - how a membership or role plugin hands out a capability at
     * runtime - never touches that array, so anything granted that way is invisible to
     * it. This list cannot be complete either, which is why it sits on top of the walk
     * rather than instead of it: between them, a capability has to be both granted at
     * runtime and absent from this list to slip through.
     *
     * @return array
     */
    private static function runtimeProbedCapabilities()
    {
        return (array)apply_filters('fluent_auth/headless_probed_capabilities', [
            'manage_options',
            'edit_posts',
            'upload_files',
            'edit_users',
            'activate_plugins',
            'delete_users',
            'edit_theme_options',
            'unfiltered_html',
            'moderate_comments',
            'manage_woocommerce'
        ]);
    }

    /**
     * Whether this account can change anything about the site.
     *
     * Read from `allcaps` rather than asked one capability at a time, so a capability
     * nobody here has heard of still counts. Role names live in that array too and are
     * skipped: they are how WordPress records which role granted the rest, not a power.
     *
     * @param $user \WP_User
     * @return bool
     */
    private static function canChangeTheSite($user)
    {
        /*
         * A network administrator holds everything everywhere, and core says so by
         * short-circuiting has_cap() before allcaps is ever consulted - so the walk below
         * reads a super admin sitting on a subscriber role as harmless.
         */
        if (is_multisite() && is_super_admin($user->ID)) {
            return true;
        }

        /*
         * Asked through user_can() first, because allcaps is the stored set and not the
         * effective one: `user_has_cap` is how a membership or role plugin grants a
         * capability at runtime, and none of that reaches the array. A short list is
         * enough here - it is a backstop under the walk, not the boundary itself.
         */
        foreach (self::runtimeProbedCapabilities() as $capability) {
            if (user_can($user, $capability)) {
                return true;
            }
        }

        $harmless = (array)self::harmlessCapabilities();
        $roles = array_values($user->roles);

        foreach ((array)$user->allcaps as $capability => $granted) {
            if (!$granted || in_array($capability, $roles, true) || in_array($capability, $harmless, true)) {
                continue;
            }

            return true;
        }

        return false;
    }

    private function headlessLoginMayPass($user, $method)
    {
        /*
         * A browser looking at somebody else's login form is the whole reason this
         * exists. REST is not that: there is no form, no reader, and no error message
         * anybody would see - just a client that wanted a session without answering for
         * it. Such a request is refused rather than passed, and nothing is mailed to it.
         *
         * XML-RPC is tested here too and never reaches it. isUnattendedRequest() takes
         * that route out of the caller above, where the login proceeds on the password
         * alone; the test is kept because this is the one place the two are the same
         * shape, and a site that puts XML-RPC back through the factor - by answering
         * `fluent_auth/unattended_login_request` false - lands here and should be refused
         * rather than waved past on a role check.
         */
        $isApiRequest = (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
            || (defined('REST_REQUEST') && REST_REQUEST);

        /*
         * Filterable because one site's API is another's front end: a headless build
         * whose whole sign-in runs over REST may want the pass there, and a site that
         * leaves xmlrpc.php open may want it excluded from more than this.
         */
        if ((bool)apply_filters('fluent_auth/headless_pass_excludes_api', $isApiRequest, $user)) {
            return false;
        }

        /*
         * An account under attack is challenged whatever else is true, and this has to
         * ask outright rather than infer it. Reading it off `!isAvailableForUser()` only
         * caught the case where the escalation had to reach for a method the user's
         * roles do not have: with emailed codes already on for them, the dispatcher
         * returns that available method first and the escalation is never consulted, so
         * the one account the site is actively worried about was the one waved through.
         */
        if ($this->isChallengeRequired($user)) {
            return false;
        }
        /*
         * Anybody who can change the site is out - see canChangeTheSite(), which reads
         * the whole capability set rather than testing a handful of names, because the
         * handful was never going to be complete.
         */
        if (self::canChangeTheSite($user)) {
            return false;
        }

        if (DeviceRequirement::isRequiredForUser($user) || DeviceRequirement::holdsEnrolledDevice($user)) {
            return false;
        }

        // The repeated-failure fallback - see the note above.
        if (!$method->isAvailableForUser($user)) {
            return false;
        }

        /*
         * The way back to refusing every one of them. A site that would rather a visitor
         * met the handoff message than skipped the code answers false.
         */
        $allowed = (bool)apply_filters('fluent_auth/allow_headless_login_without_challenge', true, $user, $method);

        /*
         * Recorded, because letting the login past the `authenticate` chain is only half
         * of a sign-in. maybeWithholdAuthCookies() resolves the challenge again on its
         * own and refuses the cookie, so without this the caller was handed a WP_User
         * while the browser stayed signed out - a form told "success" over a session
         * that does not exist, which is worse than the error message this replaced.
         */
        if ($allowed) {
            self::$headlessPassedUsers[$user->ID] = true;
        }

        return $allowed;
    }

    /**
     * Withholds the auth cookie from a user who still owes a second factor.
     *
     * Every other check here lives on the `authenticate` chain, and a plugin that sets
     * the cookie itself - a community invitation, a checkout that signs the customer in -
     * never enters that chain. This filter sits under all of them: nothing core does
     * reaches it without the chain having already passed, so the only logins it ever
     * stops are the ones nothing else could see.
     *
     * The challenge is raised and left waiting in the cookie, and the calling plugin is
     * allowed to carry on. Wherever it sends the browser next, the visitor arrives signed
     * out and is taken to the form; once answered, they are returned to that page.
     *
     * @param $send bool
     * @param $expire int
     * @param $expiration int
     * @param $userId int  Named by core since 6.2; taken from `set_auth_cookie` before that.
     * @return bool
     */
    public function maybeWithholdAuthCookies($send, $expire = 0, $expiration = 0, $userId = 0)
    {
        $userId = (int)$userId ?: (int)$this->cookieUserId;
        $this->cookieUserId = null;

        // wp_clear_auth_cookie() runs this filter too, with no user. Nothing to decide.
        if (!$send || !$userId || self::$completingChallenge) {
            return $send;
        }

        // wp_set_auth_cookie() asks more than once per request. Same answer every time.
        if (isset(self::$withheldUsers[$userId])) {
            return false;
        }

        /*
         * A cookie minted where no browser will ever read it - see isUnattendedRequest().
         * Withholding it protects nothing, and the challenge raised alongside mailed a
         * code for a sign in no person performed: a cron task or a WP-CLI command that
         * calls wp_set_auth_cookie() did it once per run, on a timer, forever.
         */
        if ($this->isUnattendedRequest()) {
            return $send;
        }

        /*
         * Already decided, on the way in. maybeDenyHeadlessLogin() weighed this sign-in
         * and let it through; re-deciding it here on a narrower question would refuse the
         * cookie for the login it had just allowed.
         */
        if (isset(self::$headlessPassedUsers[$userId])) {
            return $send;
        }

        /*
         * The escape hatch for a site where a direct-cookie flow turns out to matter more
         * than the policy. Everything the login chain enforces stays enforced.
         */
        if (!apply_filters('fluent_auth/enforce_2fa_on_auth_cookie', true, $userId)) {
            return $send;
        }

        /*
         * A cookie re-issued to whoever is already signed in - after a session sweep, say
         * - proves nothing new and takes nothing away. Only a fresh sign in is examined.
         */
        if ($this->arrivedSignedInAs($userId)) {
            return $send;
        }

        /*
         * An administrator switching into another account. They could reset that
         * account's password from the users screen, so a second factor asked of the
         * account they are stepping into - and mailed to its owner - guards nothing.
         */
        if (self::$cookieAuthenticatedUserId && user_can(self::$cookieAuthenticatedUserId, 'edit_user', $userId)) {
            return $send;
        }

        $user = get_user_by('ID', $userId);

        if (!$user) {
            return $send;
        }

        $method = TwoFaService::getRequiredMethod($user, null, function () use ($user) {
            return $this->isChallengeRequired($user);
        });

        if (!$method) {
            return $send;
        }

        self::$withheldUsers[$userId] = true;

        $raised = $this->sendAndGet2FaConfirmFormUrl($user, 'both');

        if ($raised) {
            $this->setPendingCookie($raised['login_hash']);
        }

        return false;
    }

    /**
     * @param $cookie string
     * @param $expire int
     * @param $expiration int
     * @param $userId int
     * @return void
     */
    public function rememberCookieUser($cookie, $expire = 0, $expiration = 0, $userId = 0)
    {
        $this->cookieUserId = (int)$userId;
        self::$cookieMinted = true;
    }

    /**
     * @return void
     */
    public function rememberAppPasswordAuth()
    {
        self::$appPasswordAuthenticated = true;
    }

    /**
     * @param $cookieElements array
     * @param $user \WP_User
     * @return void
     */
    public function rememberAuthenticatedUser($cookieElements, $user)
    {
        // Only the cookie the request arrived with, and only the first time it is seen.
        if (self::$cookieMinted || self::$cookieAuthenticatedUserId || !$user instanceof \WP_User) {
            return;
        }

        self::$cookieAuthenticatedUserId = (int)$user->ID;
    }

    /**
     * Whether this request arrived signed in as this user.
     *
     * Answered from what core validated on the way in, never by validating $_COOKIE now:
     * by this point the same request may have minted a cookie and written it there.
     *
     * @param $userId int
     * @return bool
     */
    private function arrivedSignedInAs($userId)
    {
        return self::$cookieAuthenticatedUserId && self::$cookieAuthenticatedUserId === (int)$userId;
    }

    /**
     * Whether a sign in for this user was stopped at the cookie in this request.
     *
     * The plugin that set the cookie will usually go on to fire `wp_login`, and the
     * audit log must not record a success that did not happen.
     *
     * @param $userId int
     * @return bool
     */
    public static function hasWithheldCookiesFor($userId)
    {
        return isset(self::$withheldUsers[(int)$userId]);
    }

    /**
     * Forgets everything decided for the request in progress. For tests.
     *
     * @return void
     */
    public static function resetRequestState()
    {
        self::$withheldUsers = [];
        self::$headlessPassedUsers = [];
        self::$completingChallenge = false;
        self::$cookieAuthenticatedUserId = 0;
        self::$cookieMinted = false;
        self::$appPasswordAuthenticated = false;
    }

    /**
     * Sends a signed-out visitor carrying a pending challenge to its form.
     *
     * Raised through a headless login or a withheld cookie, the challenge has never been
     * shown to anyone. Whatever page the other plugin sends the browser to next is where
     * it gets shown - and, unless the challenge already knows where to return them, where
     * they are sent back to afterwards.
     *
     * One shot: the cookie is cleared before redirecting, so someone who leaves the form
     * to sign in as somebody else is not dragged back to it on every page for ten minutes.
     *
     * @return void
     */
    public function maybeResumePendingChallenge()
    {
        if (empty($_COOKIE[self::PENDING_COOKIE])) {
            return;
        }

        if (wp_doing_ajax() || wp_doing_cron() || (defined('REST_REQUEST') && REST_REQUEST) || (defined('WP_CLI') && WP_CLI)) {
            return;
        }

        if (!empty($_SERVER['REQUEST_METHOD']) && strtoupper($_SERVER['REQUEST_METHOD']) !== 'GET') {
            return;
        }

        if (is_user_logged_in()) {
            $this->clearPendingCookie();
            return;
        }

        // Already on the form, or on the login screen for something else entirely.
        if (isset($_GET['fls_2fa'])) {
            return;
        }

        global $pagenow;

        $onLoginScreen = $pagenow === 'wp-login.php';

        if ($onLoginScreen && !empty($_REQUEST['action']) && $_REQUEST['action'] !== 'login') {
            return;
        }

        $hash = sanitize_text_field(wp_unslash($_COOKIE[self::PENDING_COOKIE]));

        $this->clearPendingCookie();

        $row = $this->getPendingRow($hash);

        if (!$row || strtotime($row->valid_till) < current_time('timestamp')) {
            return;
        }

        /*
         * Where to send them afterwards, if the challenge does not already know: the
         * page they were opening, or - when auth_redirect() bounced them to the login
         * screen - the admin page it was asked to return them to.
         */
        if (!$row->redirect_intend) {
            $destination = '';

            if (!$onLoginScreen) {
                $destination = $this->getCurrentUrl();
            } elseif (!empty($_REQUEST['redirect_to']) && is_string($_REQUEST['redirect_to'])) {
                $destination = Helper::getValidatedRedirectUrl(esc_url_raw(wp_unslash($_REQUEST['redirect_to'])), '');
            }

            if ($destination) {
                flsDb()->table('fls_login_hashes')
                    ->where('id', $row->id)
                    ->update(['redirect_intend' => $destination]);
            }
        }

        wp_safe_redirect(TwoFaService::getChallengeUrl($hash));
        exit();
    }

    /**
     * Where to send the user once the challenge is answered.
     *
     * `redirect_to` is what wp-login.php and this plugin's forms send; `redirect` is
     * what WooCommerce and others send. Failing both, the page the login came from -
     * which for a form embedded in a page is exactly where they expect to end up. A
     * referer pointing at the login screen itself is no use, since a signed in visitor
     * is only bounced off it again.
     *
     * Every candidate has to be on this site, or the challenge is an open redirect.
     *
     * @return string
     */
    private function resolveRedirectIntent()
    {
        foreach (['redirect_to', 'redirect'] as $key) {
            if (empty($_REQUEST[$key]) || !is_string($_REQUEST[$key])) {
                continue;
            }

            $url = Helper::getValidatedRedirectUrl(esc_url_raw(wp_unslash($_REQUEST[$key])), '');

            if ($url) {
                return $url;
            }
        }

        $referer = wp_get_referer();

        if ($referer && !$this->isLoginScreenUrl($referer)) {
            return $referer;
        }

        return '';
    }

    /**
     * @param $url string
     * @return bool
     */
    private function isLoginScreenUrl($url)
    {
        $path = (string)parse_url($url, PHP_URL_PATH);
        $loginPath = (string)parse_url(wp_login_url(), PHP_URL_PATH);

        return ($loginPath && $path === $loginPath) || substr($path, -13) === '/wp-login.php';
    }

    /**
     * The page being requested, if it is one a visitor can be sent back to.
     *
     * @return string
     */
    private function getCurrentUrl()
    {
        if (empty($_SERVER['HTTP_HOST']) || empty($_SERVER['REQUEST_URI'])) {
            return '';
        }

        $url = (is_ssl() ? 'https' : 'http') . '://' . sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) . esc_url_raw(wp_unslash($_SERVER['REQUEST_URI']));

        return Helper::getValidatedRedirectUrl($url, '');
    }

    /**
     * The error a headless login gets back: what happened, and where to finish.
     *
     * A link for a browser, a bare address for anything else - a headless build that has
     * said its REST sign-in can resume, through `fluent_auth/2fa_challenge_resumable`, is
     * not rendering HTML, and its user is better served by a URL they can open.
     *
     * @param $method \FluentAuth\App\Services\TwoFa\BaseTwoFaMethod
     * @param $url string
     * @return string
     */
    private function getHandoffMessage($method, $url)
    {
        $text = $method->getHandoffText();

        if (wp_doing_ajax()) {
            return $text . ' <a href="' . esc_url($url) . '">' . esc_html__('Finish signing in', 'fluent-security') . '</a>';
        }

        // Not esc_url(): its &#038; is right inside an attribute and wrong in an address.
        /* translators: %s: URL of the second factor form */
        return $text . ' ' . sprintf(__('Finish signing in at %s', 'fluent-security'), esc_url_raw($url));
    }

    /**
     * @param $hash string
     * @return void
     */
    private function setPendingCookie($hash)
    {
        $_COOKIE[self::PENDING_COOKIE] = $hash;

        if (headers_sent()) {
            return;
        }

        setcookie(self::PENDING_COOKIE, $hash, [
            'expires'  => time() + self::PENDING_TIMEOUT,
            'path'     => COOKIEPATH,
            'domain'   => COOKIE_DOMAIN,
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    /**
     * @return void
     */
    private function clearPendingCookie()
    {
        unset($_COOKIE[self::PENDING_COOKIE]);

        if (headers_sent()) {
            return;
        }

        setcookie(self::PENDING_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => COOKIEPATH,
            'domain'   => COOKIE_DOMAIN,
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    /**
     * Whether this request has nobody at a keyboard waiting on it.
     *
     * XML-RPC, WP-CLI and cron are not sign-ins somebody is standing in front of. There
     * is no form to show, no cookie jar to leave a pending marker in, and no inbox
     * anybody is watching on behalf of the process - so a challenge raised here can
     * never be answered, and the code mailed for it only ever reaches somebody who did
     * not ask for it. A client with the right password retrying on a timer turns that
     * into a code every few minutes, for as long as it keeps running.
     *
     * So the second factor is not enforced on these at all, rather than enforced by
     * refusing them: refusing mails nothing but breaks every such client silently, and
     * both halves of that were reported as bugs. The trade is real and deliberate - a
     * correct password alone is enough over XML-RPC where it is left open - which is
     * what `disable_xmlrpc` is for, and it is in the recommended settings. Application
     * passwords remain the supported way in for a client that needs one.
     *
     * REST is deliberately not in this list. It carries application passwords, which are
     * exempt above it, and anything else authenticating there is answered rather than
     * waved through - see maybeDenyHeadlessLogin().
     *
     * @return bool
     */
    private function isUnattendedRequest()
    {
        $unattended = (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
            || (defined('WP_CLI') && WP_CLI)
            || wp_doing_cron();

        /*
         * The way back for a site that would rather XML-RPC met the factor it would meet
         * anywhere else, and the seam these are tested through - a constant cannot be
         * undefined once set, so a test that defined one would change every test after it.
         */
        return (bool)apply_filters('fluent_auth/unattended_login_request', $unattended);
    }

    /**
     * Whether a browser will come back for a challenge raised now.
     *
     * The pending cookie is what carries an unanswered challenge to the next page load,
     * so a request with no cookie jar cannot be handed one. REST is the case that
     * matters: a client posting a username and password to a route of its own gets no
     * form, keeps no cookie, and cannot spend the code - so it is refused outright and
     * nothing is mailed. Ajax is the opposite and is left alone: there is a real browser
     * behind it, the pending cookie works, and the error carries the link to finish.
     *
     * @return bool
     */
    private function canResumeInBrowser()
    {
        $canResume = !(defined('REST_REQUEST') && REST_REQUEST);

        return (bool)apply_filters('fluent_auth/2fa_challenge_resumable', $canResume);
    }

    /**
     * Whether this request has anywhere to put a challenge form.
     *
     * The plugin's own AJAX forms mark themselves and get the form back as JSON. Anybody
     * else's AJAX login, a REST call or an XML-RPC call has no such place: a redirect
     * breaks the caller and a JSON body is not what it was expecting.
     *
     * @return bool
     */
    private function cannotShowChallenge()
    {
        if (wp_doing_ajax()) {
            /*
             * `_is_fls_form` is the marker login_helper.js puts on our own posts, and for
             * a while it was the only way to be recognised. A host that renders its own
             * login form posts to its own admin-ajax action and cannot set it, so every
             * such login was read as headless and handed the WP_Error meant for XML-RPC -
             * which a form that prints the message it gets back shows as a plain error.
             *
             * The filter is the way in for those. Answer true and the challenge comes
             * back as `two_fa_form` for the caller to mount; window.fluentAuthLogin
             * .mountChallenge() is what wires it once it is on the page.
             */
            return !apply_filters(
                'fluent_auth/can_render_2fa_inline',
                !empty($_REQUEST['_is_fls_form'])
            );
        }

        return (defined('REST_REQUEST') && REST_REQUEST)
            || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST);
    }

    /**
     * Counts a wrong answer and burns the challenge once the cap is reached.
     *
     * @param $logHash object
     * @param $user \WP_User
     * @param $method \FluentAuth\App\Services\TwoFa\BaseTwoFaMethod
     * @return void
     */
    private function recordFailedAttempt($logHash, $user, $method)
    {
        $usedCount = $logHash->used_count + 1;

        $update = [
            'used_count' => $usedCount,
            'updated_at' => current_time('mysql')
        ];

        // Burn the challenge once the cap is reached, it must not stay guessable.
        if ($usedCount >= self::MAX_VERIFY_ATTEMPTS) {
            $update['status'] = 'failed';
        }

        flsDb()->table('fls_login_hashes')
            ->where('id', $logHash->id)
            ->update($update);

        /*
         * The first factor already succeeded to get here, so nothing has been recorded
         * as a failure yet. Reporting it makes these attempts visible to the IP attempt
         * limit - without that an attacker who has the password can just log in again
         * for a fresh challenge and keep guessing forever.
         */
        Helper::setLoginMedia($method->getLoginMedia());

        do_action('wp_login_failed', $user->user_login, new \WP_Error(
            'fls_invalid_2fa_code',
            __('Invalid two factor authentication code', 'fluent-security')
        ));
    }

    /**
     * @param $hash string
     * @return object|null
     */
    private function getPendingRow($hash)
    {
        $hash = sanitize_text_field($hash);

        if (!$hash) {
            return null;
        }

        return flsDb()->table('fls_login_hashes')
            ->where('login_hash', $hash)
            ->whereIn('use_type', TwoFaService::getAllUseTypes())
            ->where('status', 'issued')
            ->orderBy('id', 'DESC')
            ->first();
    }

    /**
     * Burns a challenge so it can no longer be guessed.
     *
     * @param $logHash object
     * @return void
     */
    private function invalidate2FaCode($logHash)
    {
        if ($logHash->status === 'failed') {
            return;
        }

        flsDb()->table('fls_login_hashes')
            ->where('id', $logHash->id)
            ->update([
                'status'     => 'failed',
                'updated_at' => current_time('mysql')
            ]);
    }

    /**
     * @param $data array
     * @return string
     */
    private function get2FaFormHtml($data = [])
    {
        $logHash = $this->getPendingRow(Arr::get($data, 'login_hash'));

        $method = $logHash ? TwoFaService::getMethodByUseType($logHash->use_type) : null;

        if (!$method) {
            $method = new EmailTwoFaMethod();
        }

        return $method->renderForm($data);
    }
}
