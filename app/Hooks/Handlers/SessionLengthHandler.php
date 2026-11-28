<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class SessionLengthHandler
{
    const WP_SESSION_DAYS = 2;

    const WP_REMEMBER_DAYS = 14;

    const MAX_DAYS = 365;

    public function register()
    {
        add_filter('auth_cookie_expiration', [$this, 'filterExpiration'], 10, 3);
        add_filter('login_form_defaults', [$this, 'filterLoginFormDefaults']);
        add_action('login_footer', [$this, 'checkRememberMeOnWpLogin']);
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
