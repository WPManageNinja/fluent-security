<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class GithubAuthService
{
    public static function getAuthRedirect($state = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        // The callback URL carries its own query, and add_query_arg() does not encode
        // values. Encoded, it reaches GitHub whole; see getAppRedirect().
        $params = [
            'client_id'    => rawurlencode($config['github_client_id']),
            'redirect_uri' => rawurlencode(self::getAppRedirect()),
            'scope'        => 'user',
            'state'        => rawurlencode($state)
        ];

        return add_query_arg($params, 'https://github.com/login/oauth/authorize');
    }

    public static function getTokenByCode($code)
    {
        $postUrl = 'https://github.com/login/oauth/access_token';
        $params = self::getAuthConfirmParams($code);

        $response = wp_remote_post($postUrl, [
            'body'    => $params,
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        return Arr::get($data, 'access_token');
    }

    public static function getAuthConfirmParams($code = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        return [
            'client_id'     => $config['github_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'code'          => $code,
            'client_secret' => $config['github_client_secret']
        ];
    }

    public static function getDataByAccessToken($token)
    {
        $headers = [
            'Accept'        => 'application/json',
            'Authorization' => 'Bearer ' . $token
        ];

        $response = wp_remote_get('https://api.github.com/user', [
            'headers' => $headers
        ]);

        if(is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if(!$data || empty($data['login'])) {
            return new \WP_Error('api_error', __('API Error when authenticate via github', 'fluent-security'));
        }

        /*
         * Always resolve through /user/emails, which is the only endpoint that tells us
         * whether an address is verified. The public profile email from /user carries no
         * such flag, and it is what an existing WordPress account gets matched on.
         */
        $email = self::getPrimaryEmail($headers);

        if (empty($email)) {
            return new \WP_Error('email_error', __('We could not get a verified email address from your Github account. Please verify your email with Github and try again', 'fluent-security'));
        }

        return [
            'full_name' => Arr::get($data, 'name'),
            'user_url' => Arr::get($data, 'blog'),
            'email' => $email,
            'username' => Arr::get($data, 'login'),
            'description' => Arr::get($data, 'bio')
        ];
    }

    private static function getPrimaryEmail($headers)
    {
        $response = wp_remote_get('https://api.github.com/user/emails', [
            'headers' => $headers
        ]);

        if (is_wp_error($response)) {
            return '';
        }

        $emails = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($emails)) {
            return '';
        }

        foreach ($emails as $entry) {
            if (!empty($entry['primary']) && !empty($entry['verified'])) {
                return Arr::get($entry, 'email', '');
            }
        }

        // No verified primary: fall back to any verified address rather than none.
        foreach ($emails as $entry) {
            if (!empty($entry['verified'])) {
                return Arr::get($entry, 'email', '');
            }
        }

        return '';
    }

    /**
     * The callback URL: the one the settings screen shows, the authorize link sends and
     * the token exchange posts.
     *
     * It used to end in &fs_type=confirm. The authorize link sent it unencoded, so that
     * & split it, GitHub read redirect_uri as ".../wp-login.php?fs_auth=github" and never
     * passed fs_type back. GitHub apps that match redirect URIs exactly then refused the
     * sign-in ("The redirect_uri is not associated with this application"), because the
     * settings screen told admins to register the longer URL. Without fs_type, GitHub
     * receives exactly the address it received before, so sites that work keep working.
     * The callback needs nothing more: SocialAuthHandler::handleGitHubActions() treats a
     * GitHub request that carries a code as the confirm step.
     */
    public static function getAppRedirect()
    {
        return add_query_arg([
            'fs_auth' => 'github',
        ], wp_login_url());
    }
}
