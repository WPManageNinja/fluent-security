<?php

namespace FluentAuth\App\Hooks\Handlers;

use FluentAuth\App\Helpers\Arr;

class ServerModeHandler
{

    public function register()
    {
        if (!$this->isEnabled()) {
            return;
        }

        add_filter('fluent_security/app_vars', function ($vars) {
            $vars['has_server_mode'] = 'yes';
            return $vars;
        });

        add_filter('fluent_auth/validated_redirect', function ($validated, $location) {
            // check if the location is a child site
            $authSites = get_option('__fls_child_sites', []);
            if (empty($authSites)) {
                return $validated;
            }

            $locationSiteDomain = parse_url($location, PHP_URL_HOST);

            foreach ($authSites as $authSite) {
                $childSiteUrl = $authSite['site_url'];
                if (!$childSiteUrl) {
                    continue;
                }

                // child site domain
                $childSiteDomain = parse_url($childSiteUrl, PHP_URL_HOST);
                if ($locationSiteDomain === $childSiteDomain) {
                    return $location;
                }
            }

            return $validated;
        }, 99, 2);

        add_action('init', [$this, 'maybeRemoteLoginInit'], 1);

        add_filter('login_redirect', [$this, 'maybeRemoteLoginRedirect'], 9999999, 3);

    }

    public function maybeRemoteLoginInit()
    {
        if (isset($_REQUEST['fluent_client_id'])) {
            $clientId = sanitize_text_field($_REQUEST['fluent_client_id']);
            $authSites = get_option('__fls_child_sites', []);
            if (!isset($authSites[$clientId])) {
                return;
            }

            $currentUserId = get_current_user_id();
            if ($currentUserId) {
                $this->redirectToChildSite($authSites[$clientId], $currentUserId);
            } else {
                // set the cookie for 10 minutes
                setcookie('__fls_auth_client_id', $clientId, time() + 10 * 60, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
            }
        }
    }

    private function redirectToChildSite($siteConfig, $userId, $redirect = true)
    {
        $token = wp_generate_password(32, false) . '___' . $userId;
        update_user_meta($userId, '__flsc_temp_token', $token);
        $tokenData = [
            'fluent_auth_token' => $token
        ];

        $redirectTo = add_query_arg($tokenData, $siteConfig['callback_url']);

        if ($redirect) {
            wp_redirect($redirectTo);
            exit();
        }
        return $redirectTo;
    }

    public function maybeRemoteLoginRedirect($redirect_to, $intentRedirectTo, $user)
    {
        // check cookie
        if (isset($_COOKIE['__fls_auth_client_id'])) {
            $clientId = sanitize_text_field($_COOKIE['__fls_auth_client_id']);
            $authSites = get_option('__fls_child_sites', []);
            if (!isset($authSites[$clientId])) {
                return $redirect_to;
            }

            // delete the cookie
            setcookie('__fls_auth_client_id', $clientId, time() - 99999, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);

            $siteConfig = $authSites[$clientId];

            return $this->redirectToChildSite($siteConfig, $user->ID, false);
        }

        return $redirect_to;
    }

    public function isEnabled()
    {
        return defined('FLUENT_AUTH_SERVER_MODE') && FLUENT_AUTH_SERVER_MODE;
    }
}
