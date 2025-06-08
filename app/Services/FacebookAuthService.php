<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class FacebookAuthService
{

    public static function getAuthRedirect($state = '')
    {
        $config = Helper::getSocialAuthSettings('edit');
        $apiVersion = !empty($config['facebook_api_version']) ? $config['facebook_api_version'] : 'v12.0';

        $params = [
            'client_id'     => $config['facebook_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'state'         => $state,
            'response_type' => 'code',
            'scope'         => 'email,public_profile',
            'auth_type'     => 'rerequest'
        ];
        return add_query_arg($params, "https://www.facebook.com/{$apiVersion}/dialog/oauth");
    }

    public static function getTokenByCode($code)
    {
        $config = Helper::getSocialAuthSettings('edit');
        $apiVersion = !empty($config['facebook_api_version']) ? $config['facebook_api_version'] : 'v12.0';

        $postUrl = "https://graph.facebook.com/{$apiVersion}/oauth/access_token";
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
            return new \WP_Error('token_error', __('Sorry! There was an error when fetching token for Facebook authentication. Please try again', 'fluent-security'));
        }

        return $data['access_token'];
    }

    public static function getAuthConfirmParams($code = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        return [
            'client_id'     => $config['facebook_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'client_secret' => $config['facebook_client_secret'],
            'code'          => $code
        ];
    }

    public static function getDataByAccessToken($token)
    {
        $config = Helper::getSocialAuthSettings('edit');
        $apiVersion = !empty($config['facebook_api_version']) ? $config['facebook_api_version'] : 'v12.0';

        $fields = 'id,name,email';
        $url = "https://graph.facebook.com/{$apiVersion}/me?fields={$fields}&access_token={$token}";

        $response = wp_remote_get($url, [
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $userData = json_decode($body, true);

        if (empty($userData['email'])) {
            return new \WP_Error('payload_error', __('Sorry! There was an error when fetching data for Facebook authentication. Please try again', 'fluent-security'));
        }

        $username = Arr::get($userData, 'email');
        $emailArray = explode('@', $username);
        if (count($emailArray)) {
            $username = $emailArray[0];
        }

        return [
            'full_name' => Arr::get($userData, 'name'),
            'email'     => Arr::get($userData, 'email'),
            'username'  => $username
        ];
    }

    public static function getAppRedirect()
    {
        return add_query_arg(['fs_auth' => 'facebook'], wp_login_url());
    }

}
