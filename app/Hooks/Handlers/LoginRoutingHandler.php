<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Helper;

class LoginRoutingHandler
{
    public function register()
    {
        // Social callbacks and pending second factors run first, at priority 1.
        add_action('login_init', [$this, 'maybeRedirect'], 5);
    }

    public function maybeRedirect()
    {
        $url = $this->getRedirectUrl();
        if (!$url) {
            return;
        }

        nocache_headers();
        if (!empty($_GET['reauth'])) {
            // Core clears stale cookies on this guest entrypoint too.
            wp_clear_auth_cookie();
        }
        wp_safe_redirect($url);
        exit;
    }

    public function getRedirectUrl()
    {
        global $pagenow;
        if ((defined('FLUENT_AUTH_DISABLE_LOGIN_ROUTING') && FLUENT_AUTH_DISABLE_LOGIN_ROUTING)
            || $pagenow !== 'wp-login.php'
            || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
            || is_user_logged_in()) {
            return '';
        }

        // Anything beyond ordinary navigation belongs to core or another handler.
        // In particular, do not move an action appended to wp_login_url().
        if (array_diff(array_keys($_GET), ['action', 'redirect_to', 'reauth'])
            || (isset($_REQUEST['action']) && $_REQUEST['action'] !== 'login')) {
            return '';
        }

        $settings = Helper::getAuthFormsSettings();
        if ($settings['enabled'] !== 'yes' || $settings['redirect_wp_login'] !== 'yes'
            || !(new CustomAuthHandler())->isEnabled()) {
            return '';
        }

        $page = self::getLoginPage($settings['login_page_id']);
        $url = $page ? get_permalink($page) : '';
        if (!$url || wp_parse_url($url, PHP_URL_HOST) !== wp_parse_url(home_url(), PHP_URL_HOST)
            || wp_parse_url($url, PHP_URL_PORT) !== wp_parse_url(home_url(), PHP_URL_PORT)
            || wp_parse_url($url, PHP_URL_PATH) === wp_parse_url(site_url('wp-login.php'), PHP_URL_PATH)) {
            return '';
        }

        if (isset($_GET['redirect_to']) && is_string($_GET['redirect_to'])) {
            $redirect = Helper::getValidatedRedirectUrl(esc_url_raw(wp_unslash($_GET['redirect_to'])), '');
            if ($redirect) {
                $url = add_query_arg('redirect_to', $redirect, $url);
            }
        }

        return $url;
    }

    /** @return \WP_Post|false */
    public static function getLoginPage($id)
    {
        if ((!is_int($id) && !is_string($id)) || !ctype_digit((string) $id) || !$id) {
            return false;
        }
        $page = get_post((int) $id);
        if (!$page || $page->post_type !== 'page' || $page->post_status !== 'publish' || $page->post_password) {
            return false;
        }

        preg_match_all('/' . get_shortcode_regex(['fluent_auth', 'fluent_auth_login']) . '/s', $page->post_content, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            // [[fluent_auth]] is literal text, not a usable login form.
            if (($match[1] !== '[' || $match[6] !== ']') && shortcode_exists($match[2])) {
                return $page;
            }
        }
        return false;
    }
}
