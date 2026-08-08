<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\BrowserDetection;
use FluentAuth\App\Helpers\Helper;

class PasskeyAuditService
{
    public static function log($status, $user, $description = '', $errorCode = '')
    {
        if (!Helper::getSetting('enable_auth_logs')) {
            return false;
        }

        if (!$user || empty($user->ID)) {
            return false;
        }

        $agent = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $browserDetection = new BrowserDetection();
        $browser = $browserDetection->getBrowser($agent);
        $os = $browserDetection->getOS($agent);

        return flsDb()->table('fls_auth_logs')->insert([
            'username'    => $user->user_login,
            'user_id'     => (int)$user->ID,
            'count'       => 1,
            'agent'       => $agent,
            'browser'     => Arr::get($browser, 'browser_name'),
            'device_os'   => Arr::get($os, 'os_family'),
            'ip'          => Helper::getIp(),
            'status'      => sanitize_text_field($status),
            'error_code'  => sanitize_text_field($errorCode),
            'media'       => 'passkey',
            'description' => sanitize_text_field($description),
            'created_at'  => current_time('mysql'),
            'updated_at'  => current_time('mysql')
        ]);
    }
}
