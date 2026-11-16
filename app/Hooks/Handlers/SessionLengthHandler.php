<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class SessionLengthHandler
{
    const WP_SESSION_DAYS = 2;

    const WP_REMEMBER_DAYS = 14;

    const MAX_DAYS = 365;

    private $newSessions = [];
    private $cookieCandidate;

    public function register()
    {
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
            && get_class(\WP_Session_Tokens::get_instance($userId)) === 'WP_User_Meta_Session_Tokens'
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

        global $wpdb;
        list($userId, $token) = $candidate;
        $key = hash('sha256', $token);
        $loginId = null;
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $row = $wpdb->get_row($wpdb->prepare(
                "SELECT umeta_id, meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s ORDER BY umeta_id LIMIT 1",
                $userId, 'session_tokens'
            ));
            $sessions = $row ? maybe_unserialize($row->meta_value) : [];
            $incoming = is_array($sessions) ? ($sessions[$key] ?? null) : null;
            $ends = is_int($incoming) ? $incoming : ($incoming['expiration'] ?? 0);
            if (!$ends || $ends < time()) {
                return false; // A concurrent revoke must never be undone by issuing this cookie.
            }
            if ($attempt === 0) {
                $loginId = $incoming['fls_login_id'] ?? '';
                if (!isset($this->newSessions[$loginId])) {
                    return $send; // Existing/supplied token reissue does not start a new sign-in.
                }
                unset($this->newSessions[$loginId]);
            }

            $others = [];
            foreach ($sessions as $verifier => $session) {
                $ends = is_int($session) ? $session : ($session['expiration'] ?? 0);
                if ($verifier !== $key && $ends >= time()) {
                    $others[$verifier] = (int)($session['login'] ?? 0);
                }
            }
            if (count($others) < $limit) {
                return $send;
            }
            uksort($others, function ($a, $b) use ($others) {
                return ($others[$a] <=> $others[$b]) ?: strcmp($a, $b);
            });
            foreach (array_slice(array_keys($others), 0, count($others) - $limit + 1) as $old) {
                unset($sessions[$old]);
            }

            // Match the exact snapshot: retry a competing login/logout instead of restoring its old tokens.
            $updated = $wpdb->query($wpdb->prepare(
                "UPDATE {$wpdb->usermeta} SET meta_value = %s WHERE umeta_id = %d AND BINARY meta_value = BINARY %s",
                maybe_serialize($sessions), $row->umeta_id, $row->meta_value
            ));
            if ($updated === 1) {
                wp_cache_delete($userId, 'user_meta');
                return $send;
            }
            if ($updated === false) {
                break;
            }
        }
        // Only the sign-in is affected; normal authenticated traffic never reaches this path.
        wp_die(esc_html__('We could not finish signing you in. Please try again.', 'fluent-security'), '', ['response' => 503]);
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
