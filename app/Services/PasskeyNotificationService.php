<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\BrowserDetection;
use FluentAuth\App\Helpers\Helper;

class PasskeyNotificationService
{
    public static function notifyUser($user, $action, $passkeyName = '')
    {
        if (!$user || empty($user->user_email)) {
            return false;
        }

        if (!apply_filters('fluent_auth/passkey_send_user_notification', true, $action, $user, $passkeyName)) {
            return false;
        }

        $types = [
            'registered' => 'passkey_registered_to_user',
            'removed'    => 'passkey_removed_to_user'
        ];

        $emailType = Arr::get($types, $action);
        if (!$emailType) {
            return false;
        }

        $setting = SystemEmailService::getEmailSettingsByType($emailType);
        $status = Arr::get($setting, 'status', 'system');

        if ($status === 'disabled') {
            return false;
        }

        $defaults = SystemEmailService::getEmailDefaults();
        $defaultEmail = Arr::get($defaults, $emailType . '.email', []);
        $email = $status === 'active' ? Arr::get($setting, 'email', []) : $defaultEmail;
        $email = wp_parse_args($email, $defaultEmail);

        $subject = Arr::get($email, 'subject', '');
        $body = Arr::get($email, 'body', '');

        if (!$subject || !$body) {
            return false;
        }

        $user = self::getContextUser($user, $passkeyName);
        $replaces = self::getPasskeyReplaces($user);

        $subject = strtr($subject, $replaces);
        $body = strtr($body, $replaces);

        $parser = new SmartCodeParser();
        $subject = $parser->parse($subject, $user);
        $body = SystemEmailService::withHtmlTemplate($parser->parse($body, $user), null, $user);

        try {
            return wp_mail(
                self::getRecipient($user),
                $subject,
                $body,
                self::getEmailHeaders()
            );
        } catch (\Throwable $e) {
            return false;
        }
    }

    private static function getContextUser($user, $passkeyName)
    {
        $contextUser = get_user_by('ID', $user->ID);
        if (!$contextUser) {
            $contextUser = $user;
        }

        $agent = !empty($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $browserDetection = new BrowserDetection();
        $browser = Arr::get($browserDetection->getOS($agent), 'os_family') . ' / ' . Arr::get($browserDetection->getBrowser($agent), 'browser_name');

        $contextUser->passkey_name = sanitize_text_field($passkeyName ?: __('Passkey', 'fluent-security'));
        $contextUser->ip_address = Helper::getIp();
        $contextUser->browser = trim($browser, ' /');
        $contextUser->event_time = date_i18n(get_option('date_format') . ' ' . get_option('time_format'), current_time('timestamp'));

        return $contextUser;
    }

    private static function getPasskeyReplaces($user)
    {
        $values = [
            'passkey_name' => $user->passkey_name,
            'ip_address'   => $user->ip_address,
            'browser'      => $user->browser,
            'event_time'   => $user->event_time
        ];

        $replaces = [];
        foreach ($values as $key => $value) {
            $replaces['{{user.' . $key . '}}'] = $value;
            $replaces['##user.' . $key . '##'] = $value;
        }

        return $replaces;
    }

    private static function getRecipient($user)
    {
        if (!empty($user->display_name)) {
            return $user->display_name . ' <' . $user->user_email . '>';
        }

        return $user->user_email;
    }

    private static function getEmailHeaders()
    {
        $headers = ['Content-Type: text/html; charset=UTF-8'];
        $settings = SystemEmailService::getGlobalSettings();
        $templateSettings = Arr::get($settings, 'template_settings', Arr::get($settings, 'global_settings', []));

        if (!empty($templateSettings['from_email'])) {
            $fromName = Arr::get($templateSettings, 'from_name', '');
            $headers[] = $fromName ? 'From: ' . $fromName . ' <' . $templateSettings['from_email'] . '>' : 'From: <' . $templateSettings['from_email'] . '>';
        }

        if (!empty($templateSettings['reply_to_email'])) {
            $replyToName = Arr::get($templateSettings, 'reply_to_name', '');
            $headers[] = $replyToName ? 'Reply-To: ' . $replyToName . ' <' . $templateSettings['reply_to_email'] . '>' : 'Reply-To: <' . $templateSettings['reply_to_email'] . '>';
        }

        return $headers;
    }
}
