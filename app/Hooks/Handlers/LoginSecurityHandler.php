<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\IpRules;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;

class LoginSecurityHandler
{
    private $failedLogged = false;

    private $appPasswordBlocked = null;

    public function register()
    {
        add_filter('authenticate', [$this, 'maybeCheckLoginAttempts'], 999, 3);
        add_filter('lostpassword_errors', [$this, 'maybeBlockPasswordReset'], 10, 2);
        add_action('wp_login_failed', [$this, 'logFailedAuth'], 10, 2);
        add_action('wp_login', [$this, 'logAuthSuccess'], 10, 2);

        /*
         * Application Password auth (REST / XML-RPC over Basic auth) never runs through
         * the `authenticate` filter chain: wp_validate_application_password() calls
         * wp_authenticate_application_password() directly. Without these two hooks the
         * attempt limit above simply does not apply to it and nothing gets logged.
         */
        add_filter('wp_is_application_passwords_available', [$this, 'maybeBlockAppPasswordAuth'], 999);
        add_action('application_password_failed_authentication', [$this, 'logFailedAppPasswordAuth'], 10, 1);

        add_filter('fluent_auth/2fa_challenge_required', [$this, 'maybeRequireLoginChallenge'], 10, 2);

        /*
         * A social login never reaches the `authenticate` chain either - AuthService sets
         * the cookie itself once the provider has vouched for the address. Google saying
         * who somebody is does not say where they are, so the address restriction has to
         * be applied here as well or it is one OAuth button away from being bypassed.
         */
        add_filter('fluent_auth/can_user_login', [$this, 'maybeDenyRestrictedLocation'], 999, 3);
    }

    /**
     * @param $canLogin bool|\WP_Error
     * @param $user \WP_User
     * @param $provider string
     * @return bool|\WP_Error
     */
    public function maybeDenyRestrictedLocation($canLogin, $user, $provider = '')
    {
        if (is_wp_error($canLogin) || !$canLogin || !IpRules::deniesSignIn($user)) {
            return $canLogin;
        }

        $this->logBlockedAuth($user, $user->user_login);

        /*
         * A plain false rather than a WP_Error when there is no provider: AuthService only
         * reads an error object on the provider path, and an error returned anywhere else
         * is truthy enough to be mistaken for permission.
         */
        if (!$provider) {
            return false;
        }

        return new \WP_Error(
            'login_error',
            __('Your account can only be used from an approved location.', 'fluent-security')
        );
    }

    /**
     * Decides whether a correct password alone should be enough for this login.
     *
     * The IP limit only ever sees one source at a time, so a spread out attack never
     * trips it. Counting per account catches that - but blocking an account outright
     * would let anyone who knows a username lock its owner out on demand. So instead of
     * denying, we ask for the emailed code: the owner still gets in, a guesser does not.
     *
     * @param $required bool
     * @param $user \WP_User
     * @return bool
     */
    public function maybeRequireLoginChallenge($required, $user)
    {
        if ($required || !$user instanceof \WP_User) {
            return $required;
        }

        if (!Helper::isLoginSecurityEnabled()) {
            return false;
        }

        $minutes = (int)Helper::getSetting('login_try_timing');
        $limit = (int)Helper::getSetting('login_try_limit');

        if (!$minutes || !$limit) {
            return false;
        }

        /*
         * Higher than the per IP limit because this aggregates every source. Anything
         * reaching it has already spread itself across addresses to dodge the IP block.
         */
        $threshold = (int)apply_filters('fluent_auth/account_attempt_limit', $limit * 3, $user);

        if ($threshold < 1) {
            return false;
        }

        // A place this user has already signed in from successfully is not challenged.
        if ($this->isTrustedIpForUser($user)) {
            return false;
        }

        global $wpdb;

        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);

        $count = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `user_id` = %d AND `created_at` > %s AND `status` IN ('failed','blocked')",
            $user->ID,
            $dateTime
        ));

        return $count >= $threshold;
    }

    /**
     * Whether this user has ever completed a login from the current IP.
     *
     * Matched on user_id rather than the submitted username so casing and
     * email-vs-login variants all resolve to the same account.
     *
     * @param $user \WP_User
     * @return bool
     */
    public function isTrustedIpForUser($user)
    {
        if (!$user instanceof \WP_User) {
            return false;
        }

        global $wpdb;

        $found = $wpdb->get_var($wpdb->prepare(
            "SELECT `id` FROM {$wpdb->prefix}fls_auth_logs WHERE `user_id` = %d AND `ip` = %s AND `status` = 'success' LIMIT 1",
            $user->ID,
            Helper::getIp()
        ));

        return (bool)$found;
    }

    /**
     * Applies the login attempt limit to Application Password authentication.
     *
     * Runs before any password hashing is done, so a blocked IP costs us nothing.
     *
     * @param $status bool
     * @return bool
     */
    public function maybeBlockAppPasswordAuth($status)
    {
        if (!$status) {
            return $status;
        }

        /*
         * Only interfere with actual API auth attempts. This filter also gates the
         * Application Passwords UI on the profile screen, and those requests carry no
         * Basic auth credentials - we must not hide the UI from a legitimate admin.
         * This mirrors the check core itself does in wp_validate_application_password().
         */
        if (!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
            return $status;
        }

        /*
         * Core calls wp_is_application_passwords_available() more than once per request.
         * Resolve the block once, otherwise we would count the same attempt twice.
         */
        if ($this->appPasswordBlocked !== null) {
            return $this->appPasswordBlocked ? false : $status;
        }

        $username = sanitize_user(wp_unslash($_SERVER['PHP_AUTH_USER']));

        /*
         * The address restriction is about the account, so this path has to resolve one
         * before it can apply it - there is no $user here, only whatever was typed into the
         * Basic auth header. An unknown name is left alone: core will reject it anyway, and
         * refusing differently for names that exist is how a login form tells an attacker
         * which accounts are real.
         */
        $appUser = get_user_by('login', $username) ?: get_user_by('email', $username);

        if ($appUser && IpRules::deniesSignIn($appUser)) {
            $this->appPasswordBlocked = true;
            $this->logBlockedAuth($appUser, $username, 'app_password');

            return false;
        }

        $isLimitExceeded = $this->checkLoginAttempt(null, $username);

        $this->appPasswordBlocked = is_wp_error($isLimitExceeded);

        if (!$this->appPasswordBlocked) {
            return $status;
        }

        $this->logBlockedAuth(
            new \WP_Error('blocked', __('Too many failed application password attempts', 'fluent-security')),
            $username,
            'app_password'
        );

        return false;
    }

    /**
     * Logs a failed Application Password attempt so it counts towards the attempt limit.
     *
     * @param $error \WP_Error
     * @return void
     */
    public function logFailedAppPasswordAuth($error)
    {
        /*
         * XML-RPC sends credentials in the request body rather than Basic auth headers,
         * and that path already fires `wp_login_failed`. Bailing here keeps us from
         * logging the same attempt twice.
         */
        if (!isset($_SERVER['PHP_AUTH_USER'])) {
            return;
        }

        $username = sanitize_user(wp_unslash($_SERVER['PHP_AUTH_USER']));

        $this->logFailedAuth($username, $error, 'app_password');
    }

    /**
     * @return string
     */
    private function getUserAgent()
    {
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            return '';
        }

        return sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT']));
    }

    /**
     * @param $user \WP_User | \WP_Error
     * @param $username
     * @param $password
     * @return bool|mixed|\WP_Error|\WP_User
     */
    public function maybeCheckLoginAttempts($user, $username, $password)
    {
        if (empty($_POST) && !$username) {
            return $user;
        }

        /*
         * Deliberately outside the emailed token exemption below.
         *
         * That exemption exists so a locked out administrator can get back in with a magic
         * link, which is right for a rate limit - the limit is about guessing, and somebody
         * reading their own inbox is not guessing. The address restriction is about *where*
         * they are, and a rule saying administrators may only sign in from the office is
         * worth nothing if asking the site to email you a link is a way around it.
         */
        if (IpRules::deniesSignIn($user)) {
            $this->logBlockedAuth($user, $username);

            return new \WP_Error(
                'login_error',
                __('Your account can only be used from an approved location.', 'fluent-security')
            );
        }

        /*
         * Redeeming an emailed token is not a password guess, so the block does not
         * apply - but everything below it still does, or a magic link would become a
         * way to skip two factor authentication.
         */
        if (!Helper::isTokenVerifiedLogin()) {
            $isLimitExceeded = $this->checkLoginAttempt($user, $username);

            if (is_wp_error($isLimitExceeded)) {
                $this->logBlockedAuth($user, $username);
                return $isLimitExceeded;
            }
        }

        if (is_wp_error($user)) {
            $errorCode = $user->get_error_code();
            if ($errorCode == 'invalid_username' || $errorCode == 'incorrect_password') {
                return new \WP_Error(
                    $errorCode,
                    __('<strong>Error</strong>: The username or the password is invalid. Please try different combination.', 'fluent-security')
                );
            }
            return $user;
        }

        do_action('fluent_auth/login_attempts_checked', $user);

        return $user;
    }

    /**
     * @param $errors \WP_Error
     * @param $userData \WP_User || false
     * @return mixed|\WP_Error
     */
    public function maybeBlockPasswordReset($errors, $userData)
    {
        if (!Helper::isLoginSecurityEnabled()) {
            return $errors;
        }

        $minutes = Helper::getSetting('login_try_timing');
        $limit = Helper::getSetting('login_try_limit');

        if (!$minutes || !$limit) {
            return $errors;
        }

        global $wpdb;
        $ip = Helper::getIp();
        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);

        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` IN ('failed','blocked', 'password_reset')", $ip, $dateTime));

        if (!$count || $count < $limit) {

            $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

            $userAgent = $this->getUserAgent();

            $logData = [
                'username'   => ($userData) ? $userData->user_login : '',
                'agent'      => $userAgent,
                'ip'         => Helper::getIp(),
                'browser'    => $browserDetection->getBrowser($userAgent)['browser_name'],
                'device_os'  => $browserDetection->getOS($userAgent)['os_family'],
                'status'     => 'password_reset',
                'media'      => 'web',
                'created_at' => current_time('mysql'),
                'updated_at' => current_time('mysql'),
            ];

            /*
             * Reset requests for an account that does not exist have no user_id. The
             * column has to be left out entirely rather than set to '' or null - the
             * query builder sends both as an empty string, which a BIGINT column
             * rejects outright under MySQL strict mode.
             */
            if ($userData) {
                $logData['user_id'] = $userData->ID;
            }

            // Just log here
            flsDb()->table('fls_auth_logs')->insert($logData);

            return $errors;
        }

        /* translators: %d: munites */
        return new \WP_Error('blocked', sprintf(__('You are blocked for next %d minutes. Please try after that time', 'fluent-security'), $minutes));
    }

    /**
     * @param $username string
     * @param $error \WP_Error
     * @param $media string
     * @return void
     */
    public function logFailedAuth($username, $error, $media = '')
    {
        if ($this->failedLogged || !Helper::isLoginSecurityEnabled()) {
            return;
        }

        /*
         * The password was right; the request just had nowhere to show the second step
         * (see TwoFaHandler::maybeDenyHeadlessLogin). Counting that as a guess would let
         * an honest user lock their own address out by retrying a popup login form.
         */
        if ($error->get_error_code() === 'fls_2fa_required') {
            return;
        }

        if (!$media) {
            // `wp_login_failed` passes no media, so honour whatever the flow set.
            $media = Helper::getLoginMedia();
        }

        global $wpdb;

        $byField = 'login';
        if (is_email($username)) {
            $byField = 'email';
        }

        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $user = get_user_by($byField, $username);

        $userAgent = $this->getUserAgent();

        $data = [
            'username'    => $username,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql'),
            'agent'       => $userAgent,
            'ip'          => Helper::getIp(),
            'error_code'  => $error->get_error_code(),
            'description' => $error->get_error_message(),
            'browser'     => $browserDetection->getBrowser($userAgent)['browser_name'],
            'device_os'   => $browserDetection->getOS($userAgent)['os_family'],
            'status'      => 'failed',
            'media'       => $media,
            'count'       => 1
        ];

        if ($user) {
            $data['user_id'] = $user->ID;
        }

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);

        $this->failedLogged = true;
    }

    /**
     * @param $user \WP_User
     * @return void
     */
    public function logAuthSuccess($userName, $user)
    {
        if (!Helper::isLoginSecurityEnabled()) {
            return;
        }

        /*
         * The plugin that fired `wp_login` believes it signed this user in; the cookie
         * was withheld pending a second factor. The success is logged when that arrives.
         */
        if (TwoFaHandler::hasWithheldCookiesFor($user->ID)) {
            return;
        }

        $media = Helper::getLoginMedia();

        global $wpdb;

        // Check if HTTP_USER_AGENT exists before accessing it
        $agent = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : 'Unknown User Agent';

        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $data = [
            'username'    => $user->user_login,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql'),
            'agent'       => sanitize_text_field($agent),
            'ip'          => Helper::getIp(),
            'browser'     => $browserDetection->getBrowser($agent)['browser_name'],
            'device_os'   => $browserDetection->getOS($agent)['os_family'],
            'description' => '',
            'media'       => $media,
            'status'      => 'success',
            'user_id'     => $user->ID
        ];

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);

        do_action('fluent_auth/user_login_success', $user);

        $this->maybeSendSuccessEmail($user, $media);
    }

    /**
     * @param $user \WP_User | \WP_Error
     * @param $username string
     * @param $media string
     * @return void
     */
    private function logBlockedAuth($user, $username, $media = 'web')
    {
        global $wpdb;

        $ipAddress = Helper::getIp();

        /*
         * Look back over the same window checkLoginAttempt() uses. With a fixed window
         * the two lookups can disagree when login_try_timing is longer than it, and we
         * would insert a second blocked row for an IP that is already blocked.
         */
        $minutes = (int)Helper::getSetting('login_try_timing');
        if (!$minutes) {
            $minutes = 60;
        }

        // get previous blocked row for this ip within the block window
        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);
        $prev = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` = 'blocked' LIMIT 1", $ipAddress, $dateTime));

        if ($prev) {
            $wpdb->update($wpdb->prefix . 'fls_auth_logs', [
                'updated_at' => current_time('mysql'),
                'count'      => $prev->count + 1
            ], [
                'id' => $prev->id
            ]);
            $this->failedLogged = true;
            return;
        }

        $agent = $this->getUserAgent();
        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();
        $browserData = $browserDetection->getBrowser($agent);

        $data = [
            'username'    => $username,
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql'),
            'agent'       => $agent,
            'ip'          => $ipAddress,
            'error_code'  => 'blocked',
            'browser'     => Arr::get($browserData, 'browser_name'),
            'device_os'   => Arr::get($browserData, 'os_family'),
            'description' => 'Blocked by Fluent Auth',
            'status'      => 'blocked',
            'media'       => $media,
            'count'       => 1
        ];

        if (!is_wp_error($user)) {
            $data['user_id'] = $user->ID;
        }

        $wpdb->insert("{$wpdb->prefix}fls_auth_logs", $data);

        $this->failedLogged = true;

        $this->maybeSendBlockedEmail($user, $username);
    }

    private function checkLoginAttempt($user, $userName)
    {
        if (!Helper::isLoginSecurityEnabled()) {
            return true;
        }

        $ip = Helper::getIp();

        /*
         * The lists are consulted before the attempt limit, and before the limit's own
         * settings are read, because neither list is part of it: a blocked address stays
         * blocked on a site that has turned the limit off, and an allowed one is exempt
         * from counting however the limit is configured.
         *
         * Both callers log the outcome after this returns, so a refusal here is still
         * recorded - see IpRules, which is deliberate about not suppressing that.
         */
        if (IpRules::isBlocked($ip)) {
            return new \WP_Error(
                'login_error',
                __('Logins from your network are not permitted on this site.', 'fluent-security')
            );
        }

        if (IpRules::isAllowed($ip)) {
            return true;
        }

        $minutes = Helper::getSetting('login_try_timing');
        $limit = Helper::getSetting('login_try_limit');

        if (!$minutes || !$limit) {
            return true;
        }

        global $wpdb;
        $dateTime = date('Y-m-d H:i:s', current_time('timestamp') - $minutes * 60);

        // check if already blocked then no need to create a new row
        $blocked = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` = 'blocked' LIMIT 1", $ip, $dateTime));

        if ($blocked) {
            /*
             * Refresh `created_at` so the lockout keeps sliding for as long as the
             * attempts keep coming. The attempt itself is counted by logBlockedAuth(),
             * which every caller runs right after we return the error - counting it
             * here as well would record each blocked attempt twice.
             */
            $wpdb->update($wpdb->prefix . 'fls_auth_logs', [
                'created_at' => current_time('mysql')
            ], [
                'id' => $blocked->id
            ]);
        } else {
            $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}fls_auth_logs WHERE `ip` = %s AND `created_at` > %s AND `status` IN ('failed','blocked')", $ip, $dateTime));

            if (!$count || $count < $limit) {
                return true;
            }
        }

        /* translators: %d: munites */
        return new \WP_Error('login_error', sprintf(__('You are trying too much. Please try after %d minutes', 'fluent-security'), $minutes));
    }

    /**
     * @param $user \WP_User
     * @return bool
     */
    private function maybeSendSuccessEmail($user, $media = '')
    {
        $notificationUserRoles = Helper::getSetting('notification_user_roles');
        if (!$notificationUserRoles || !array_intersect($notificationUserRoles, (array)$user->roles)) {
            return false;
        }

        $adminEmail = Helper::getSetting('notification_email');
        if (!$adminEmail) {
            return false;
        }

        $adminEmail = str_replace('{admin_email}', get_bloginfo('admin_email'), $adminEmail);
        if (!$adminEmail) {
            return false;
        }

        $userEditLInk = add_query_arg('user_id', $user->ID, self_admin_url('user-edit.php'));

        $agent = $this->getUserAgent();
        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $userRoles = (array)$user->roles;

        $roleNames = implode(', ', $userRoles);

        $ip = Helper::getIp();
        $infoHtml = '<ul style="padding-left:20px;line-height:25px;font-size: 14px;background: #f9f9f9;padding-top: 20px;padding-bottom: 20px;font-family: monospace;">';
        $infoHtml .= '<li><b>Site URL:</b> <a href="' . site_url() . '">' . site_url() . '</a></li>';
        $infoHtml .= '<li><b>Username:</b> <a href="' . $userEditLInk . '">' . $user->user_login . '</a></li>';
        $infoHtml .= '<li><b>User Role:</b> ' . $roleNames . '</li>';
        if ($media && $media != 'web') {
            $infoHtml .= '<li><b>Media:</b> ' . $media . '</li>';
        }
        $infoHtml .= '<li><b>Email:</b> ' . $user->user_email . '</li>';
        $infoHtml .= '<li><b>Name:</b> ' . $user->first_name . ' ' . $user->last_name . '</li>';
        $infoHtml .= '<li><b>Login IP Address:</b> <a href="https://ipinfo.io/' . $ip . '">' . $ip . '</a></li>';
        $infoHtml .= '<li><b>Browser:</b> ' . $browserDetection->getOS($agent)['os_family'] . ' / ' . $browserDetection->getBrowser($agent)['browser_name'] . '</li>';
        $infoHtml .= '</ul>';

        $lines = [
            '<p style="font-size: 16px; line-height: 25px;">Hello there, <br />The following user has been logged in to your site. Here is the details:</p>',
            $infoHtml
        ];

        $siteName = get_bloginfo('name');
        $data = [
            'body'        => implode('', $lines),
            'pre_header'  => 'Login success at ' . $siteName,
            'show_footer' => true
        ];

        $body = Helper::loadView('notification', $data);
        $subject = '[' . $siteName . '] Login success for ' . $user->user_login;

        $headers = array('Content-Type: text/html; charset=UTF-8');

        return \wp_mail($adminEmail, $subject, $body, $headers);
    }

    /**
     * @param $user \WP_User | \WP_Error
     * @param $userName string
     * @return bool
     */
    private function maybeSendBlockedEmail($user, $userName)
    {
        if (Helper::getSetting('notify_on_blocked') !== 'yes') {
            return false;
        }

        $adminEmail = Helper::getSetting('notification_email');
        if (!$adminEmail) {
            return false;
        }

        $adminEmail = str_replace('{admin_email}', get_bloginfo('admin_email'), $adminEmail);
        if (!$adminEmail) {
            return false;
        }

        // get last send email time
        $lastSendTime = get_option('fls_last_blocked_email_send_time', 0);
        if ($lastSendTime && (time() - $lastSendTime) < 60) {
            return false;
        }

        update_option('fls_last_blocked_email_send_time', time(), false);

        $agent = $this->getUserAgent();
        $browserDetection = new \FluentAuth\App\Helpers\BrowserDetection();

        $ip = Helper::getIp();
        $infoHtml = '<ul style="padding-left:20px;line-height:25px;font-size: 14px;background: #f9f9f9;padding-top: 20px;padding-bottom: 20px;font-family: monospace;">';
        $infoHtml .= '<li><b>Site URL:</b> <a href="' . site_url() . '">' . site_url() . '</a></li>';
        $infoHtml .= '<li><b>Username:</b> ' . $userName . '</li>';
        $infoHtml .= '<li><b>Login IP Address:</b> <a href="https://ipinfo.io/' . $ip . '">' . $ip . '</a></li>';
        $infoHtml .= '<li><b>Browser:</b> ' . $browserDetection->getOS($agent)['os_family'] . ' / ' . $browserDetection->getBrowser($agent)['browser_name'] . '</li>';

        if (is_wp_error($user)) {
            $infoHtml .= '<li>' . wp_kses_post($user->get_error_message()) . '</li>';
        } else if ($user instanceof \WP_User) {
            $userEditLInk = add_query_arg('user_id', $user->ID, self_admin_url('user-edit.php'));
            $infoHtml .= '<li><b>Username:</b> <a href="' . $userEditLInk . '">' . $user->user_login . '</a></li>';
            $infoHtml .= '<li><b>Email:</b> ' . $user->user_email . '</li>';
            $infoHtml .= '<li><b>Name:</b> ' . $user->first_name . ' ' . $user->last_name . '</li>';
        }
        $infoHtml .= '</ul>';

        $lines = [
            '<p style="font-size: 16px; line-height: 25px;">Hello there, <br />The following user has been blocked from logged in from your site. Here is the details:</p>',
            $infoHtml
        ];

        $siteName = get_bloginfo('name');
        $data = [
            'body'        => implode('', $lines),
            'pre_header'  => 'Blocked from login ' . $siteName,
            'show_footer' => true
        ];

        $body = Helper::loadView('notification', $data);
        $subject = '[' . $siteName . '] Blocked from login - ' . $userName;

        $headers = array('Content-Type: text/html; charset=UTF-8');

        return \wp_mail($adminEmail, $subject, $body, $headers);
    }
}
