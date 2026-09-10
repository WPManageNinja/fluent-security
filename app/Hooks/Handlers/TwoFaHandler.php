<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
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
     * True only while verify2FaEmailCode() completes a sign in whose proof has just been
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
     * The user core is about to issue cookies for, caught from `set_auth_cookie` because
     * `send_auth_cookies` only started naming them in WordPress 6.2.
     */
    private $cookieUserId = null;

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
        add_action('set_auth_cookie', [$this, 'rememberCookieUser'], 10, 4);
        add_filter('send_auth_cookies', [$this, 'maybeWithholdAuthCookies'], 999, 4);

        // A challenge raised where no form could be shown is picked up on the next page.
        add_action('template_redirect', [$this, 'maybeResumePendingChallenge'], 1);
        add_action('login_init', [$this, 'maybeResumePendingChallenge'], 1);

        add_action('login_form_fls_2fa_email', [$this, 'render2FaForm'], 1);
        add_action('wp_ajax_nopriv_fluent_auth_2fa_email', [$this, 'verify2FaEmailCode']);
        add_action('wp_ajax_fluent_auth_2fa_email', function () {
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
        });
    }

    public function render2FaForm()
    {
        if (!isset($_GET['fls_2fa']) || $_GET['fls_2fa'] != 'email') {
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
        login_footer();
        exit();
    }

    public function maybe2FaRedirect($user)
    {
        if (self::$completingChallenge) {
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
            wp_send_json([
                'load_2fa'    => 'yes',
                'two_fa_form' => $this->get2FaFormHtml($return)
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
    public function sendAndGet2FaConfirmFormUrl($user, $return = 'url', $redirectIntend = null)
    {
        $challengeRequired = $this->isChallengeRequired($user);

        $method = TwoFaService::getRequiredMethod($user, null, $challengeRequired);

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
            'use_type'        => $challengeRequired ? $method->getChallengeKey() : $method->getKey(),
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

        $redirectTo = $this->getChallengeUrl($hash);

        if ($return === 'url') {
            return $redirectTo;
        }

        return [
            'redirect_to' => $redirectTo,
            'login_hash'  => $hash
        ];
    }

    public function verify2FaEmailCode()
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
        $user = wp_signon(array(
                'user_login'    => $user->user_login,
                'user_password' => '',
                'remember'      => (bool)strpos($logHash->login_hash, '-auth')
            )
        );

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

                wp_send_json([
                    'redirect' => $redirectTo
                ]);
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

        $method = TwoFaService::getRequiredMethod($user, null, $this->isChallengeRequired($user));

        if (!$method) {
            return $user;
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
        if ($this->isSignedInByCookie($userId)) {
            return $send;
        }

        $user = get_user_by('ID', $userId);

        if (!$user) {
            return $send;
        }

        $method = TwoFaService::getRequiredMethod($user, null, $this->isChallengeRequired($user));

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
    }

    /**
     * Whether this request arrived with a valid logged-in cookie for this user.
     *
     * @param $userId int
     * @return bool
     */
    private function isSignedInByCookie($userId)
    {
        if (empty($_COOKIE[LOGGED_IN_COOKIE])) {
            return false;
        }

        return (int)wp_validate_auth_cookie($_COOKIE[LOGGED_IN_COOKIE], 'logged_in') === (int)$userId;
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
        self::$completingChallenge = false;
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

        $onLoginScreen = (bool)did_action('login_init');

        if ($onLoginScreen && !empty($_REQUEST['action']) && $_REQUEST['action'] !== 'login') {
            return;
        }

        $hash = sanitize_text_field(wp_unslash($_COOKIE[self::PENDING_COOKIE]));

        $this->clearPendingCookie();

        $row = $this->getPendingRow($hash);

        if (!$row || strtotime($row->valid_till) < current_time('timestamp')) {
            return;
        }

        if (!$row->redirect_intend && !$onLoginScreen) {
            $current = $this->getCurrentUrl();

            if ($current) {
                flsDb()->table('fls_login_hashes')
                    ->where('id', $row->id)
                    ->update(['redirect_intend' => $current]);
            }
        }

        wp_safe_redirect($this->getChallengeUrl($hash));
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
     * @param $hash string
     * @return string
     */
    private function getChallengeUrl($hash)
    {
        return add_query_arg([
            'fls_2fa'    => 'email',
            'login_hash' => $hash,
            'action'     => 'fls_2fa_email'
        ], wp_login_url());
    }

    /**
     * The error a headless login gets back: what happened, and where to finish.
     *
     * A link for a browser, a bare address for anything else - a REST or XML-RPC client
     * is not rendering HTML, and its user is better served by a URL they can open.
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

        /* translators: %s: URL of the second factor form */
        return $text . ' ' . sprintf(__('Finish signing in at %s', 'fluent-security'), esc_url($url));
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
            return empty($_REQUEST['_is_fls_form']);
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
