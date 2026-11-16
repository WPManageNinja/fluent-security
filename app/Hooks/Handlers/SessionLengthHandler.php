<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\NativeSessionTokens;

class SessionLengthHandler
{
    const WP_SESSION_DAYS = 2;

    const WP_REMEMBER_DAYS = 14;

    const MAX_DAYS = 365;

    private $newSessions = [];
    private $cookieCandidate;

    public function register()
    {
        add_filter('session_token_manager', [NativeSessionTokens::class, 'selectManager'], PHP_INT_MAX);
        add_filter('auth_cookie_expiration', [$this, 'filterExpiration'], 10, 3);
        add_filter('login_form_defaults', [$this, 'filterLoginFormDefaults']);
        add_action('login_footer', [$this, 'checkRememberMeOnWpLogin']);
        add_filter('attach_session_information', [$this, 'markNewSession'], PHP_INT_MAX, 2);
        add_action('set_logged_in_cookie', [$this, 'captureSession'], 10, 6);
        add_filter('send_auth_cookies', [$this, 'limitSessions'], PHP_INT_MAX, 6);
    }

    public static function supportsLimit($userId = 0)
    {
        $userId = $userId ?: get_current_user_id();
        return !is_multisite()
            && get_class(\WP_Session_Tokens::get_instance($userId)) === NativeSessionTokens::class
            && apply_filters('get_user_metadata', null, $userId, 'session_tokens', true, 'user') === null;
    }

    public function markNewSession($session, $userId)
    {
        if (self::sessionLimit() > 0 && self::supportsLimit($userId)) {
            $session['fls_login_id'] = wp_generate_uuid4();
            $this->newSessions[$session['fls_login_id']] = true;
        }
        return $session;
    }

    public function captureSession($cookie, $expire, $expiration, $userId, $scheme, $token)
    {
        $this->cookieCandidate = [$userId, $token];
    }

    public function limitSessions($send, $expire = 0, $expiration = 0, $userId = 0, $scheme = '', $token = '')
    {
        // Before WordPress 6.2 the filter has no context; the cookie action already has it.
        $candidate = func_num_args() === 1 ? $this->cookieCandidate : [$userId, $token];
        $this->cookieCandidate = null;
        $limit = self::sessionLimit();
        if (!$send || !$limit || !$candidate || !$candidate[0] || !$candidate[1]
            || !self::supportsLimit($candidate[0])) {
            return $send;
        }

        list($userId, $token) = $candidate;
        $manager = \WP_Session_Tokens::get_instance($userId);
        if (!($manager instanceof NativeSessionTokens)) {
            return $send;
        }
        $session = $manager->get($token);
        if (!$session) {
            return false;
        }
        $loginId = $session['fls_login_id'] ?? '';
        if (!isset($this->newSessions[$loginId])) {
            return $send;
        }
        unset($this->newSessions[$loginId]);
        return $manager->pruneForLogin($token, $limit) ? $send : false;
    }

    public function filterExpiration($length, $userId = 0, $remember = false)
    {
        $days = $remember ? self::rememberDays() : self::sessionDays();
        $wpDays = $remember ? self::WP_REMEMBER_DAYS : self::WP_SESSION_DAYS;

        // Untouched settings leave the length to WordPress and any other filter.
        if ($days === $wpDays) {
            return $length;
        }

        // $length starts at core's default, so only a value above it came from another hook.
        if ($length > $wpDays * DAY_IN_SECONDS) {
            return max((int)$length, $days * DAY_IN_SECONDS);
        }

        return $days * DAY_IN_SECONDS;
    }

    private static function sessionLimit()
    {
        $limit = Helper::getSetting('session_limit');
        return is_scalar($limit) && !is_bool($limit) && ctype_digit((string)$limit) && (float)$limit <= 100
            ? (int)$limit : 0;
    }

    public function filterLoginFormDefaults($defaults)
    {
        $defaults['value_remember'] = self::rememberByDefault();
        return $defaults;
    }

    public function checkRememberMeOnWpLogin()
    {
        // After a failed POST, wp-login.php already shows what the user chose.
        if (!self::rememberByDefault() || (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST')) {
            return;
        }

        echo '<script>(function(){var el=document.getElementById("rememberme");if(el){el.checked=true;}})();</script>';
    }

    public static function sessionDays()
    {
        return self::clampDays(Helper::getSetting('session_days'), self::WP_SESSION_DAYS);
    }

    public static function rememberDays()
    {
        return max(self::sessionDays(), self::clampDays(Helper::getSetting('remember_days'), self::WP_REMEMBER_DAYS));
    }

    public static function rememberByDefault()
    {
        return Helper::getSetting('remember_default') !== 'no';
    }

    public static function clampDays($value, $fallback)
    {
        if (!is_numeric($value)) {
            return $fallback;
        }

        return max(1, min((int)$value, self::MAX_DAYS));
    }
}
