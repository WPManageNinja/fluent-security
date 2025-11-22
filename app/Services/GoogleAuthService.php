<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class GoogleAuthService
{
    public static function getAuthRedirect($state = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        $params = [
            'response_type' => 'code',
            'client_id'     => $config['google_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'scope'         => 'openid%20email%20profile',
            'state'         => $state,
            'nonce'         => wp_generate_uuid4()
        ];

        return add_query_arg($params, 'https://accounts.google.com/o/oauth2/v2/auth');
    }

    public static function getTokenByCode($code)
    {
        $postUrl = 'https://oauth2.googleapis.com/token';
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

        if (!$data || empty($data['id_token'])) {
            return new \WP_Error('token_error', __('Sorry! There has an error when fetching token for google authentication. Please try again', 'fluent-security'));
        }

        return Arr::get($data, 'id_token');
    }


    public static function verifyClientToken($idToken)
    {
        $postUrl = 'https://oauth2.googleapis.com/tokeninfo';

        $response = wp_remote_post($postUrl, [
            'body'    => [
                'id_token' => $idToken
            ],
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $config = Helper::getSocialAuthSettings('edit');

        if ($config['google_client_id'] != Arr::get($data, 'aud')) {
            return new \WP_Error('token_error', __('Sorry! Invalid token audience for google authentication. Please try again', 'fluent-security'));
        }

        return $data;
    }


    public static function getAuthConfirmParams($code = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        return [
            'client_id'     => $config['google_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'code'          => $code,
            'grant_type'    => 'authorization_code',
            'client_secret' => $config['google_client_secret']
        ];
    }

    public static function getDataByIdToken($token)
    {
        $tokenParts = explode(".", $token);
        $tokenPayload = base64_decode($tokenParts[1]);
        $jwtPayload = json_decode($tokenPayload, true);

        if (empty($jwtPayload['email'])) {
            return new \WP_Error('payload_error', __('Sorry! There has an error when fetching data for google authentication. Please try again', 'fluent-security'));
        }

        $username = Arr::get($jwtPayload, 'email');
        $emailArray = explode('@', $username);
        if (count($emailArray)) {
            $username = $emailArray[0];
        }

        return [
            'full_name' => Arr::get($jwtPayload, 'name'),
            'email'     => Arr::get($jwtPayload, 'email'),
            'username'  => $username
        ];
    }

    public static function getAppRedirect()
    {

        if (defined('FLUENT_AUTH_SOCIAL_REDIRECT_URL') && FLUENT_AUTH_SOCIAL_REDIRECT_URL) {
            return FLUENT_AUTH_SOCIAL_REDIRECT_URL;
        }

        return wp_login_url();
    }
}
