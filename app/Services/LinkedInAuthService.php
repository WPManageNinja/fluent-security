<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class LinkedInAuthService
{
    public static function getAuthRedirect($state = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        $params = http_build_query([
            'response_type' => 'code',
            'client_id'     => $config['linkedin_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'scope'         => 'openid profile email',
            'state'         => $state
        ]);

        return 'https://www.linkedin.com/oauth/v2/authorization?' . $params;
    }

    public static function getTokenByCode($code)
    {
        $postUrl = 'https://www.linkedin.com/oauth/v2/accessToken';
        $params = self::getAuthConfirmParams($code);

        $response = wp_remote_post($postUrl, [
            'body'    => $params,
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!$data || empty($data['access_token'])) {
            return new \WP_Error('token_error', __('Sorry! There has an error when fetching token for LinkedIn authentication. Please try again', 'fluent-security'));
        }

        return Arr::get($data, 'access_token');
    }

    public static function getAuthConfirmParams($code = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        return [
            'client_id'     => $config['linkedin_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'code'          => $code,
            'grant_type'    => 'authorization_code',
            'client_secret' => $config['linkedin_client_secret']
        ];
    }

    public static function getDataByAccessToken($token)
    {
        $response = wp_remote_get('https://api.linkedin.com/v2/userinfo', [
            'headers' => [
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer ' . $token
            ]
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!$data || empty($data['email'])) {
            return new \WP_Error('payload_error', __('Sorry! There has an error when fetching data for LinkedIn authentication. Please try again', 'fluent-security'));
        }

        $fullName = trim(Arr::get($data, 'given_name', '') . ' ' . Arr::get($data, 'family_name', ''));
        if (!$fullName) {
            $fullName = Arr::get($data, 'name');
        }

        $username = Arr::get($data, 'email');
        $emailArray = explode('@', $username);
        if (count($emailArray)) {
            $username = $emailArray[0];
        }

        return [
            'full_name' => $fullName,
            'email'     => Arr::get($data, 'email'),
            'username'  => $username
        ];
    }

    public static function getAppRedirect()
    {
        return add_query_arg(['fs_auth' => 'linkedin'], wp_login_url());
    }
}
