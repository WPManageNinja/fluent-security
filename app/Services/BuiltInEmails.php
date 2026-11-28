<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

/**
 * What each email says when it is left on Built-in.
 *
 * FluentAuth's own emails (the 2FA code, the magic link, the signup code) are built here
 * and sent from here, so the preview on the editor screen is the email itself.
 *
 * The rest are WordPress's. Core builds them inline, and calling those functions for a
 * preview would issue a real reset key and spend whatever link the admin has open. So
 * their text is mirrored below, word for word and through core's own translations: a
 * msgid only finds its translation when it matches core's exactly, line breaks included.
 */
class BuiltInEmails
{
    public static function twoFaCode($user, $code, $autoLoginUrl, $validityMinutes)
    {
        $blogName = html_entity_decode(get_bloginfo('name'), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        /* translators: %1$s: Site Name, %2$d: login code */
        $subject = sprintf(__('Your login code for %1$s - %2$d', 'fluent-security'), $blogName, $code);

        $lines = [
            /* translators: %s: User's Display Name  */
            sprintf(__('Hello %s,', 'fluent-security'), $user->display_name),
            /* translators: %s: Site Name  */
            sprintf(__('Someone asked to sign in to %s. Here is the code to type into the login form:', 'fluent-security'), $blogName),
            '<b>' . __('Your Login Code: ', 'fluent-security') . '</b>',
            '<p style="font-size: 22px;border: 2px dashed #555454;padding: 5px 10px;text-align: center;background: #fffaca;letter-spacing: 7px;color: #555454;display:block;">' . $code . '</p>',
            /* translators: %d: Minute  */
            sprintf(__('This code will expire in %d minutes and can only be used once.', 'fluent-security'), $validityMinutes),
            ' ',
            '<hr />'
        ];

        $callToAction = false;

        if ($autoLoginUrl) {
            $lines[] = ' ';
            $lines[] = __('Or you can sign in by tapping the button below.', 'fluent-security');
            $callToAction = [
                /* translators: %s: Site Name  */
                'btn_text' => sprintf(__('Sign in to %s', 'fluent-security'), $blogName),
                'url'      => $autoLoginUrl
            ];
        }

        $footerLines = [
            ' ',
            __('If you did not make this request, you can safely ignore this email.', 'fluent-security')
        ];

        return [
            'subject' => $subject,
            'body'    => self::magicLayout($subject, $lines, $callToAction, $footerLines)
        ];
    }

    public static function magicLink($user, $loginUrl, $validityMinutes)
    {
        /* translators: %s: Site Name  */
        $subject = sprintf(__('Sign in to %s', 'fluent-security'), get_bloginfo('name'));

        $lines = [
            /* translators: %s: user's display name  */
            sprintf(__('Hello %s,', 'fluent-security'), $user->display_name),
            /* translators: %s: Site Name  */
            sprintf(__('Click the link below to sign in to your %s account', 'fluent-security'), get_bloginfo('name')),
            /* translators: %d: Minute  */
            sprintf(__('This link will expire in %d minutes and can only be used once.', 'fluent-security'), $validityMinutes)
        ];

        $callToAction = [
            /* translators: %s: Site Name  */
            'btn_text' => sprintf(__('Sign in to %s', 'fluent-security'), get_bloginfo('name')),
            'url'      => $loginUrl
        ];

        $footerLines = [
            __('If the button above does not work, paste this link into your web browser:', 'fluent-security'),
            esc_url($loginUrl),
            ' ',
            __('If you did not make this request, you can safely ignore this email.', 'fluent-security')
        ];

        return [
            'subject' => $subject,
            'body'    => self::magicLayout($subject, $lines, $callToAction, $footerLines)
        ];
    }

    /**
     * The signup code email before its layout: the developer filters run on this message,
     * then signupLayout() wraps it.
     */
    public static function signupCode($formData, $code)
    {
        /* translators: %s: Site Name */
        $subject = sprintf(__('Your registration verification code for %s', 'fluent-security'), get_bloginfo('name'));

        $pStart = '<p style="font-family: Arial, sans-serif; font-size: 16px; font-weight: normal; margin: 0; margin-bottom: 16px;">';

        $firstName = esc_html(sanitize_text_field(wp_unslash((string)Arr::get($formData, 'first_name'))));

        /* translators: %s: First Name */
        $message = $pStart . sprintf(__('Hello %s,', 'fluent-security'), $firstName) . '</p>' .
            $pStart . __('Thanks for signing up. Enter the code below on the registration page to finish setting up your account.', 'fluent-security') . '</p>' .
            /* translators: %s: Verification code */
            $pStart . '<b>' . sprintf(__('Verification Code: %s', 'fluent-security'), $code) . '</b></p>' .
            '<br />' .
            $pStart . __('The code works for 10 minutes. If you did not ask for it, you can ignore this email.', 'fluent-security') . '</p>';

        return [
            'subject' => $subject,
            'body'    => $message
        ];
    }

    public static function signupLayout($message)
    {
        return Helper::loadView('notification', [
            'body'        => $message,
            'pre_header'  => __('Activate your account', 'fluent-security'),
            'show_footer' => false
        ]);
    }

    /**
     * The built-in email for the editor screen, filled in with the signed-in admin.
     *
     * @return array|null subject, body, and format: 'html' or 'text'.
     */
    public static function preview($emailId, $user)
    {
        $siteName = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
        $sampleKey = 'sample-key';

        switch ($emailId) {
            case 'two_fa_email_to_user':
                $email = self::twoFaCode($user, '123456', home_url('/'), 10);
                return self::html($email);

            case 'magic_email_to_user':
                $minutes = (int)apply_filters('fluent_auth/default_token_validity', 10, $user);
                $email = self::magicLink($user, home_url('/'), $minutes);
                return self::html($email);

            case 'signup_verification_to_user':
                $email = self::signupCode(['first_name' => $user->first_name ?: $user->display_name], '123456');
                $email['body'] = self::signupLayout($email['body']);
                return self::html($email);

            case 'user_registration_to_user':
                return self::text(self::wpLoginDetails($user, $siteName, $sampleKey));

            case 'fluent_auth_welcome_email_to_user':
                $registration = SystemEmailService::getEmailSettingsByType('user_registration_to_user');
                if (Arr::get($registration, 'status') !== 'active') {
                    return self::text(self::wpLoginDetails($user, $siteName, $sampleKey));
                }

                // See WPSystemEmailHandler::maybeSendCustomizedEmailOnFluentAuthSignup().
                $email = self::welcomeDefault();
                $parser = new SmartCodeParser();

                return self::html([
                    'subject' => $parser->parse(Arr::get($email, 'subject', ''), $user),
                    'body'    => SystemEmailService::withHtmlTemplate($parser->parse(Arr::get($email, 'body', ''), $user), null, $user)
                ]);

            case 'password_reset_to_user':
                // Core names the network here on multisite, not the site.
                $resetSiteName = is_multisite() ? get_network()->site_name : $siteName;

                $message = self::wp('Someone has requested a password reset for the following account:') . "\r\n\r\n";
                $message .= sprintf(self::wp('Site Name: %s'), $resetSiteName) . "\r\n\r\n";
                $message .= sprintf(self::wp('Username: %s'), $user->user_login) . "\r\n\r\n";
                $message .= self::wp('If this was a mistake, ignore this email and nothing will happen.') . "\r\n\r\n";
                $message .= self::wp('To reset your password, visit the following address:') . "\r\n\r\n";
                $message .= network_site_url('wp-login.php?login=' . rawurlencode($user->user_login) . "&key=$sampleKey&action=rp", 'login') . '&wp_lang=' . get_user_locale($user) . "\r\n\r\n";
                // Added by core when the request comes from a signed-out visitor, the usual case.
                $message .= sprintf(self::wp('This password reset request originated from the IP address %s.'), '192.0.2.10') . "\r\n";

                return self::text([
                    'subject' => sprintf(self::wp('[%s] Password Reset'), $resetSiteName),
                    'body'    => $message
                ]);

            case 'email_change_notification_to_user':
                $newEmail = 'new-address@example.com';
                $content = self::wp('Howdy ###USERNAME###,

You recently requested to have the email address on your account changed.

If this is correct, please click on the following link to change it:
###ADMIN_URL###

You can safely ignore and delete this email if you do not want to
take this action.

This email has been sent to ###EMAIL###

Regards,
All at ###SITENAME###
###SITEURL###');

                $content = str_replace('###USERNAME###', $user->user_login, $content);
                $content = str_replace('###ADMIN_URL###', esc_url(self_admin_url('profile.php?newuseremail=' . $sampleKey)), $content);
                $content = str_replace('###EMAIL###', $newEmail, $content);
                $content = str_replace('###SITENAME###', $siteName, $content);
                $content = str_replace('###SITEURL###', home_url(), $content);

                return self::text([
                    'subject' => sprintf(self::wp('[%s] Email Change Request'), $siteName),
                    'body'    => $content
                ]);

            case 'email_change_notification_after_confimation':
                $message = self::wp('Hi ###USERNAME###,

This notice confirms that your email address on ###SITENAME### was changed to ###NEW_EMAIL###.

If you did not change your email, please contact the Site Administrator at
###ADMIN_EMAIL###

This email has been sent to ###EMAIL###

Regards,
All at ###SITENAME###
###SITEURL###');

                $message = str_replace('###USERNAME###', $user->user_login, $message);
                $message = str_replace('###ADMIN_EMAIL###', get_option('admin_email'), $message);
                $message = str_replace('###NEW_EMAIL###', 'new-address@example.com', $message);
                $message = str_replace('###EMAIL###', $user->user_email, $message);
                $message = str_replace('###SITENAME###', $siteName, $message);
                $message = str_replace('###SITEURL###', home_url(), $message);

                return self::text([
                    'subject' => sprintf(self::wp('[%s] Email Changed'), $siteName),
                    'body'    => $message
                ]);

            case 'user_registration_to_admin':
                $message = sprintf(self::wp('New user registration on your site %s:'), $siteName) . "\r\n\r\n";
                $message .= sprintf(self::wp('Username: %s'), $user->user_login) . "\r\n\r\n";
                $message .= sprintf(self::wp('Email: %s'), $user->user_email) . "\r\n";

                return self::text([
                    'subject' => sprintf(self::wp('[%s] New User Registration'), $siteName),
                    'body'    => $message
                ]);

            case 'password_change_to_admin':
                return self::text([
                    'subject' => sprintf(self::wp('[%s] Password Changed'), $siteName),
                    'body'    => sprintf(self::wp('Password changed for user: %s'), $user->user_login) . "\r\n"
                ]);
        }

        return null;
    }

    /** Core changed this one: 7.1 dropped the username line, 7.0 the trailing login URL. */
    /** The welcome email's default subject and body, the same text the editor's "Use the default text" loads. */
    public static function welcomeDefault()
    {
        return Arr::get(SystemEmailService::getEmailDefaults(), 'fluent_auth_welcome_email_to_user.email', []);
    }

    private static function wpLoginDetails($user, $siteName, $key)
    {
        $version = get_bloginfo('version');
        $resetUrl = network_site_url('wp-login.php?login=' . rawurlencode($user->user_login) . "&key=$key&action=rp", 'login');

        $message = '';
        if (version_compare($version, '7.1', '<')) {
            $message = sprintf(self::wp('Username: %s'), $user->user_login) . "\r\n\r\n";
        }

        $message .= self::wp('To set your password, visit the following address:') . "\r\n\r\n";

        if (version_compare($version, '7.0', '<')) {
            $message .= $resetUrl . "\r\n\r\n" . wp_login_url() . "\r\n";
        } else {
            $message .= $resetUrl . "\r\n";
        }

        return [
            'subject' => sprintf(self::wp('[%s] Login Details'), $siteName),
            'body'    => $message
        ];
    }

    /** Core's own string, in core's own translation. */
    private static function wp($text)
    {
        // phpcs:ignore WordPress.WP.I18n.LowLevelTranslationFunction -- core's msgid, core's text domain.
        return translate($text, 'default');
    }

    private static function html($email)
    {
        return $email + ['format' => 'html'];
    }

    private static function text($email)
    {
        return $email + ['format' => 'text'];
    }

    private static function magicLayout($preHeader, $lines, $callToAction, $footerLines)
    {
        $body = Helper::loadView('magic_login.header', ['pre_header' => $preHeader]);
        $body .= Helper::loadView('magic_login.line_block', ['lines' => $lines]);

        if ($callToAction) {
            $body .= Helper::loadView('magic_login.call_to_action', $callToAction);
        }

        $body .= Helper::loadView('magic_login.line_block', ['lines' => $footerLines]);
        $body .= Helper::loadView('magic_login.footer', []);

        return $body;
    }
}
