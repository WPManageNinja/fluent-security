<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class SessionLengthHandler
{
    const WP_SESSION_DAYS = 2;

    const WP_REMEMBER_DAYS = 14;

    const MAX_DAYS = 365;

    /** @var array<string, mixed> */
    private $pending = [];
    /** @var array<string, mixed> */
    private $authenticated = [];
    private $renewed = false;

    public function register()
    {
        add_filter('auth_cookie_expiration', [$this, 'filterExpiration'], 10, 3);
        add_filter('login_form_defaults', [$this, 'filterLoginFormDefaults']);
        add_action('login_footer', [$this, 'checkRememberMeOnWpLogin']);
        add_filter('attach_session_information', [$this, 'markSession'], 10, 2);
        add_action('set_auth_cookie', [$this, 'captureCookie'], 10, 6);
        add_action('set_logged_in_cookie', [$this, 'captureCookie'], 10, 6);
        add_action('clear_auth_cookie', function () { $this->pending = []; });
        add_action('wp_login', [$this, 'persistLogin'], 1, 2);
        add_action('auth_cookie_valid', [$this, 'noteAuthenticated'], 20, 2);
        add_action('template_redirect', [$this, 'renew'], 1);
        add_action('admin_init', [$this, 'renew'], 1);
    }

    public function filterExpiration($length, $userId = 0, $remember = false)
    {
        $policy = $this->policyDays($userId);
        if ($policy && !TwoFaHandler::arrivedSignedInAs($userId)) {
            return $policy * DAY_IN_SECONDS;
        }
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

    private function policyDays($userId)
    {
        if (Helper::getSetting('persistent_login') !== 'yes') {
            return 0;
        }
        $days = Helper::getSetting('persistent_login_days');
        $user = get_user_by('ID', (int)$userId);
        if (!$user || !in_array($days, [30, 90, 180, '30', '90', '180'], true)) {
            return 0;
        }
        $scope = Helper::getSetting('persistent_login_scope');
        $roles = Helper::getSetting('persistent_login_roles');
        return $scope === 'all' || ($scope === 'selected' && is_array($roles) && !array_filter($roles, function ($role) {
            return !is_string($role);
        }) && array_intersect(
            $user->roles, $roles
        )) ? (int)$days : 0;
    }

    public static function supportsRenewal()
    {
        return apply_filters('session_token_manager', 'WP_User_Meta_Session_Tokens') === 'WP_User_Meta_Session_Tokens';
    }

    public function markSession($session, $userId)
    {
        if ($this->policyDays($userId) && !TwoFaHandler::arrivedSignedInAs($userId)) {
            $session['fls_persistent_site'] = get_current_blog_id();
            $session['fls_renewed'] = time();
        }
        return $session;
    }

    public function captureCookie($cookie, $expire, $expiration, $userId, $scheme, $token)
    {
        if ($expire || !$this->policyDays($userId) || TwoFaHandler::arrivedSignedInAs($userId)) {
            $this->pending = [];
            return;
        }
        $name = $scheme === 'logged_in' ? LOGGED_IN_COOKIE : ($scheme === 'secure_auth' ? SECURE_AUTH_COOKIE : AUTH_COOKIE);
        $this->pending['user'] = (int)$userId;
        $this->pending['expiration'] = (int)$expiration;
        $this->pending['cookies'][$name] = $cookie;
    }

    public function persistLogin($login = '', $user = null)
    {
        $pending = $this->pending;
        $this->pending = [];
        if (!$user instanceof \WP_User || ($pending['user'] ?? 0) !== (int)$user->ID || headers_sent()) {
            return;
        }
        // Core has already applied every cookie veto. Upgrade only headers it actually
        // emitted, keeping its exact payload, paths, domain, Secure and HttpOnly flags.
        $expire = $pending['expiration'] + 12 * HOUR_IN_SECONDS;
        foreach (headers_list() as $header) {
            foreach ($pending['cookies'] as $name => $cookie) {
                $pair = 'Set-Cookie: ' . $name . '=' . urlencode($cookie);
                if (strncasecmp($header, $pair . ';', strlen($pair) + 1) !== 0) {
                    continue;
                }
                $header = preg_replace('/;\s*(?:expires|max-age)=[^;]*/i', '', $header);
                header($header . '; expires=' . gmdate('D, d M Y H:i:s', $expire) . ' GMT; Max-Age=' . max(0, $expire - time()), false);
            }
        }
    }

    public function noteAuthenticated($elements, $user)
    {
        if ($user instanceof \WP_User && is_array($elements)) {
            $this->authenticated = $elements;
            $this->authenticated['user_id'] = (int)$user->ID;
        }
    }

    public function renew()
    {
        $auth = $this->authenticated;
        if ($this->renewed || !$auth || Helper::getSetting('persistent_login') !== 'yes'
            || Helper::getSetting('persistent_login_renew') !== 'yes' || $this->headersSent() || !self::supportsRenewal()
            || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET' || wp_doing_ajax() || wp_doing_cron()
            || (defined('REST_REQUEST') && REST_REQUEST) || (defined('WP_CLI') && WP_CLI)
            || (isset($_SERVER['HTTP_SEC_FETCH_DEST']) && $_SERVER['HTTP_SEC_FETCH_DEST'] !== 'document')
            || stripos(($_SERVER['HTTP_PURPOSE'] ?? '') . ($_SERVER['HTTP_SEC_PURPOSE'] ?? ''), 'prefetch') !== false) {
            return;
        }
        $userId = $auth['user_id'];
        $days = $this->policyDays($userId);
        if (!$days || get_current_user_id() !== $userId || (int)$auth['expiration'] <= time()
            || empty($auth['token']) || !hash_equals($auth['token'], wp_get_session_token())) {
            return;
        }
        $manager = \WP_Session_Tokens::get_instance($userId);
        if (get_class($manager) !== 'WP_User_Meta_Session_Tokens') {
            return;
        }
        $session = $manager->get($auth['token']);
        if (!$this->renewalDue($session)) {
            return;
        }
        $this->renewed = true;
        global $wpdb;
        // The public update() API can INSERT a revoked token. Compare the entire raw
        // existing row instead: a concurrent revoke, renewal or login makes us skip.
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT umeta_id, meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s", $userId, 'session_tokens'
        ));
        if (count($rows) !== 1) {
            return;
        }
        $row = $rows[0];
        $sessions = maybe_unserialize($row->meta_value);
        $key = hash('sha256', $auth['token']);
        if (!is_array($sessions) || !$this->renewalDue($sessions[$key] ?? null)) {
            return;
        }
        $expiration = time() + $days * DAY_IN_SECONDS;
        $sessions[$key]['expiration'] = $expiration;
        $sessions[$key]['fls_renewed'] = time();
        // Usermeta commonly has a case-insensitive collation; CAS must compare bytes,
        // including metadata supplied by other plugins, rather than collation weights.
        $changed = $wpdb->query($wpdb->prepare(
            "UPDATE `{$wpdb->usermeta}` SET meta_value = %s WHERE umeta_id = %d AND user_id = %d AND meta_key = %s AND BINARY meta_value = BINARY %s",
            maybe_serialize($sessions), $row->umeta_id, $userId, 'session_tokens', $row->meta_value
        ));
        if ($changed !== 1) {
            return;
        }
        wp_cache_delete($userId, 'user_meta');
        $duration = function ($length, $id) use ($expiration, $userId) {
            return (int)$id === $userId ? max(1, $expiration - time()) : $length;
        };
        add_filter('auth_cookie_expiration', $duration, PHP_INT_MAX, 2);
        try {
            wp_set_auth_cookie($userId, true, is_ssl(), $auth['token']);
        } finally {
            remove_filter('auth_cookie_expiration', $duration, PHP_INT_MAX);
        }
    }

    private function renewalDue($session)
    {
        return is_array($session) && ($session['fls_persistent_site'] ?? 0) === get_current_blog_id()
            && is_int($session['fls_renewed'] ?? null) && $session['fls_renewed'] <= time() - DAY_IN_SECONDS
            && is_int($session['expiration'] ?? null) && $session['expiration'] > time();
    }

    protected function headersSent()
    {
        return headers_sent();
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
