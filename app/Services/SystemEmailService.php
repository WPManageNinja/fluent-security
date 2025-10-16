<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Libs\Emogrifier\Emogrifier;

class SystemEmailService
{
    public static function getEmailIndexes()
    {
        $systemEmails = [
            // User Account Management Emails
            'user_registration_to_user'                   => [
                'name'                  => 'user_registration_to_user',
                'title'                 => __('New User Registration Notification', 'fluent-security'),
                'description'           => __('An essential email sent to new users upon account signup.', 'fluent-security'),
                'recipient'             => 'user',
                'hook'                  => 'wp_new_user_notification',
                'required_smartcodes'   => [],
                'additional_smartcodes' => [
                    '##user.password_set_url##' => __('Password Set URL', 'fluent-security'),
                ]
            ],
            'password_reset_to_user'                      => [
                'name'                  => 'password_reset_to_user',
                'title'                 => __('Password Reset Request Email', 'fluent-security'),
                'description'           => __('A security-critical email sent when a user requests to reset their password, containing a unique reset link with time-limited access.', 'fluent-security'),
                'hook'                  => 'retrieve_password',
                'recipient'             => 'user',
                'required_smartcodes'   => [
                    'user.password_reset_url'
                ],
                'additional_smartcodes' => [
                    '##user.password_set_url##' => __('Password Set URL', 'fluent-security'),
                ]
            ],
            'email_change_notification_to_user'           => [
                'name'                  => 'email_change_notification_to_user',
                'title'                 => __('Email Address Change Confirmation', 'fluent-security'),
                'description'           => __('Sent to the new email addresses to confirm and validate an email address change, providing security against unauthorized modifications.', 'fluent-security'),
                'hook'                  => 'wp_email_change_notification',
                'recipient'             => 'user',
                'required_smartcodes'   => [
                    'user.confirm_email_change_url'
                ],
                'additional_smartcodes' => [
                    '##user.confirm_email_change_url##' => __('Confirm Email Change URL', 'fluent-security'),
                    '{{new_changing_email_id}}'         => __('New Email Address', 'fluent-security'),
                ]
            ],
            'email_change_notification_after_confimation' => [
                'name'                  => 'email_change_notification_after_confimation',
                'title'                 => __('Email Address Change Notification After Confimration', 'fluent-security'),
                'description'           => __('Send email notification to the old email address of the user after confirmation.', 'fluent-security'),
                'hook'                  => 'wp_email_change_notification',
                'recipient'             => 'user',
                'required_smartcodes'   => [],
                'additional_smartcodes' => [
                    '{{user._previous_email_address_}}' => __('Previous Email Address', 'fluent-security'),
                ]
            ],
            'fluent_auth_welcome_email_to_user'           => [
                'name'                => 'fluent_auth_welcome_email_to_user',
                'title'               => __('Welcome email after sign-Up when the password is set by the user', 'fluent-security'),
                'description'         => __('A friendly welcome email sent to new users after registering via the FluentAuth Signup Form or when the password is set.', 'fluent-security'),
                'recipient'           => 'user',
                'hook'                => 'fluent_auth/after_creating_user',
                'can_disable'         => 'yes',
                'required_smartcodes' => []
            ],
            'user_registration_to_admin'                  => [
                'name'                  => 'user_registration_to_admin',
                'title'                 => __('New User Registration Notification', 'fluent-security'),
                'description'           => __('An essential email sent to the admin when someone signup.', 'fluent-security'),
                'recipient'             => 'site_admin',
                'hook'                  => 'wp_new_user_notification',
                'can_disable'           => 'yes',
                'required_smartcodes'   => [],
                'additional_smartcodes' => [
                    '##user.profile_edit_url##' => __('User Profile Edit URL', 'fluent-security'),
                ]
            ],
        ];

        $globalSettings = self::getGlobalSettings();

        foreach ($systemEmails as $key => $value) {
            $systemEmails[$key]['status'] = $globalSettings['emails'][$key]['status'] ?? 'system';
        }

        return $systemEmails;
    }

    public static function getGlobalSettings($cached = true)
    {
        static $formattedSettings = null;

        if ($cached && $formattedSettings) {
            return $formattedSettings;
        }

        $emailsDefault = self::getEmailDefaults();

        $emailConfig = [
            'logo'                 => '',
            'body_bg'              => '#f3f4f6',
            'content_bg'           => '#ffffff',
            'content_color'        => '#374151',
            'footer_content_color' => '#6b7280',
            'highlight_bg'         => 'rgb(249, 250, 251)',
            'highlight_color'      => '#374151',
            'font_family'          => '',
            'template'             => 'default',
            'email_footer'         => '',
            'from_name'            => '',
            'from_email'           => '',
            'reply_to_name'        => '',
            'reply_to_email'       => ''
        ];

        $settings = get_option('fa_system_email_settings', []);

        if (empty($settings)) {
            $formattedSettings = [
                'emails'          => $emailsDefault,
                'global_settings' => $emailConfig
            ];

            return $formattedSettings;
        }

        $emails = $settings['emails'] ?? [];
        $globalSettings = $settings['template_settings'] ?? [];

        $emails = wp_parse_args($emails, $emailsDefault);
        $globalSettings = wp_parse_args($globalSettings, $emailConfig);

        $formattedSettings = [
            'emails'            => $emails,
            'template_settings' => $globalSettings
        ];

        return $formattedSettings;
    }

    public static function getEmailSettingsByType($emailType)
    {
        $settings = self::getGlobalSettings();

        if (!$settings) {
            return [];
        }

        return Arr::get($settings, 'emails.' . $emailType, []);
    }

    public static function getEmailDefaults()
    {
        return [
            'user_registration_to_user'                   => [
                'status' => 'system',
                'email'  => [
                    'subject' => '[{{site.title}}] - Set Up Your Password',
                    'body'    => self::getDefaultEmailBody('user_registration_to_user')
                ]
            ],
            'password_reset_to_user'                      => [
                'status' => 'system',
                'email'  => [
                    'subject' => '[{{site.title}}] Password Reset',
                    'body'    => self::getDefaultEmailBody('password_reset_to_user'),
                ]
            ],
            'email_change_notification_to_user'           => [
                'status' => 'system',
                'email'  => [
                    'subject' => '[{{site.name}}] Email Change Request',
                    'body'    => self::getDefaultEmailBody('email_change_notification_to_user'),
                ]
            ],
            'email_change_notification_after_confimation' => [
                'status' => 'system',
                'email'  => [
                    'subject' => '[{{site.name}}] Your email address has been changed',
                    'body'    => self::getDefaultEmailBody('email_change_notification_after_confimation'),
                ]
            ],
            'user_registration_to_admin'                  => [
                'status' => 'system',
                'email'  => [
                    'subject' => 'New User Registration: {{user.display_name}} has joined {{site.name}}',
                    'body'    => self::getDefaultEmailBody('user_registration_to_admin'),
                ]
            ],
            'fluent_auth_welcome_email_to_user'           => [
                'status' => 'system',
                'email'  => [
                    'subject' => 'Welcome to {{site.name}} - Your Account is Ready',
                    'body'    => self::getDefaultEmailBody('fluent_auth_welcome_email_to_user'),
                ]
            ]
        ];
    }

    public static function getDefaultEmailBody($type = '')
    {
        if ($type == 'user_registration_to_user') {
            ob_start();
            ?>
            <p>Hello<strong> {{user.display_name}}</strong>,</p>
            <p>Your account has been created on <strong>{{site.title}}</strong>. To set up your password and complete
                your registration, please click the button below:</p>
            <p>&nbsp;</p>
            <p class="align-center" style="text-align: center;" align="center"><a
                    style="color: #ffffff; background-color: #0072ff; font-size: 16px; border-radius: 5px; text-decoration: none; font-weight: bold; font-style: normal; padding: 0.8rem 1rem; border-color: #0072ff;"
                    href="##user.password_set_url##">Set Your Password</a></p>
            <p>&nbsp;</p>
            <p>If the button above doesn't work, you can copy and paste this URL into your browser:</p>
            <p>##user.password_set_url##</p>
            <p>This password reset link will expire in 24 hours for security reasons.</p>
            <p>Here's your login information:</p>
            <blockquote>
                <p><strong>Username:</strong> {{user.user_login}}</p>
                <p><strong>Login URL:</strong> {{site.login_url}}</p>
            </blockquote>
            <p>&nbsp;</p>
            <hr/>
            <p>If you didn't request this email, please contact the site administrator.</p>
            <p>&nbsp;</p>
            <p>Regards</p>
            <p>All at {{site.name}}<br/>{{site.url}}</p>
            <?php
            return ob_get_clean();
        }

        if ($type == 'password_reset_to_user') {
            ob_start();
            ?>
            <p>Hello <strong>{{user.display_name}}</strong>,</p>
            <p>A password reset has been requested for the following administrator account:</p>
            <blockquote>
                <p>Your Account Username: {{user.user_login}}</p>
                <p>Your Account Email: {{user.user_email}}</p>
            </blockquote>
            <p>If you did not request this password reset, please disregard this email and no changes will be made to
                your account.</p>
            <p>To proceed with resetting your password, please click the button below:</p>
            <p>&nbsp;</p>
            <p class="align-center" style="text-align: center;" align="center"><a
                    style="color: #ffffff; background-color: #0072ff; font-size: 16px; border-radius: 5px; text-decoration: none; font-weight: bold; font-style: normal; padding: 0.8rem 1rem; border-color: #0072ff;"
                    href="##user.password_reset_url##">Reset Your Password</a></p>
            <p>&nbsp;</p>
            <p>This password reset link will expire in 24 hours for security reasons.</p>
            <p>If you're having trouble with the button above, copy and paste the URL below into your web browser:</p>
            <blockquote>
                <p>{{##user.password_reset_url##}}</p>
            </blockquote>
            <hr/>
            <p>If you did not initiate this request, please review your account security and consider changing your
                password.</p>
            <p>&nbsp;</p>
            <p>Regards</p>
            <p>All at {{site.name}}<br/>{{site.url}}</p>
            <?php
            return ob_get_clean();
        }

        if ($type == 'email_change_notification_to_user') {
            ob_start();
            ?>
            <p>Hello<b> {{user.display_name}}</b>,</p>
            <p>We received a request to change the email address associated with your <strong> {{site.name}}</strong>
                account.</p>
            <p><span style="text-decoration: underline;"><strong>Your account change details:</strong></span></p>
            <blockquote>
                <p><strong>Current Email:</strong> {{user.user_email}}</p>
                <p><strong>New Email:</strong> {{user.new_changing_email_id}} <em>(will take effect after
                        confirmation)</em></p>
            </blockquote>
            <p>To complete this process and verify your new email address, please click the confirmation button
                below.</p>
            <p>&nbsp;</p>
            <p class="align-center" style="text-align: center;" align="center"><a style="color: #ffffff; background-color: #0072ff; font-size: 16px; border-radius: 5px; text-decoration: none; font-weight: bold; font-style: normal; padding: 0.8rem 1rem; border-color: #0072ff;" href="##user.confirm_email_change_url##">Confirm Email Change</a></p>
            <p>&nbsp;</p>
            <p>If the button above doesn't work, you can copy and paste this URL into your browser:</p>
            <blockquote>
                <p>{{user.confirm_email_change_url}}</p>
            </blockquote>
            <p>This confirmation link will expire in 24 hours for security reasons. If you don't confirm within this timeframe, you'll need to submit a new email change request.</p>
            <hr/>
            <p>This email has been sent to: {{user.meta._new_email}}</p>
            <p>Regards</p>
            <p>All at {{site.name}}<br/>{{site.url}}</p>
            <?php
            return ob_get_clean();
        }

        if ($type == 'email_change_notification_after_confimation') {
            ob_start();
            ?>
            <p>Hello {{user.display_name}},</p>
            <p>This is a confirmation that the email address for your account on<strong> {{site.name}}</strong> has been successfully changed.</p>
            <p><strong>Email Change Details:</strong></p>
            <blockquote>
                <p><strong>Previous Email:</strong> {{user._previous_email_address_}}<br/><strong>New Email:</strong> {{user.user_email}}</p>
            </blockquote>
            <p>All future communications will be sent to your new email address. You can continue to use your account with the same username and password.</p>
            <blockquote>
                <p><strong>Important:</strong> If you did not authorize this change, please contact the Site Administrator immediately at {{site.admin_email}}.</p>
            </blockquote>
            <p>This notification has been sent to your previous email address ({{user._previous_email_address_}}) for security purposes.</p>
            <p>&nbsp;</p>
            <p>Regards</p>
            <p>All at {{site.name}}<br/>{{site.url}}</p>
            <?php
            return ob_get_clean();
        }
        else if ($type == 'user_registration_to_admin') {
            ob_start();
            ?>
            <p>Hello there,</p>
            <p>A new user has registered on your website ({{site.name}} - {{site.url}}).</p>
            <p><strong>New User Details:</strong></p>
            <blockquote>
                <p><strong>Username: </strong>{{user.user_login}}</p>
                <p><strong>User Email:</strong> {{user.user_email}}</p>
                <p><strong>Display Name:</strong> {{user.display_name}}</p>
                <p><strong>User Role:</strong> {{user.roles}}</p>
            </blockquote>
            <p>
                <a style="color: #ffffff; background-color: #0072ff; font-size: 16px; border-radius: 5px; text-decoration: none; font-weight: bold; font-style: normal; padding: 0.8rem 1rem; border-color: #0072ff;" href="##user.profile_edit_url##">View User Profile</a></p>
            <hr/>
            <p>This is an automated message from the fluentAuth plugin.</p>
            <?php
            return ob_get_clean();
        } else if ($type == 'fluent_auth_welcome_email_to_user') {
            ob_start();
            ?>
            <p>Hello {{user.display_name}},</p>
            <p>Thank you for signing up! Your account has been successfully created and is now ready to use. We're excited to have you join us and look forward to giving you a great experience on our website.</p>
            <p><strong>Your Account Details:</strong></p>
            <blockquote>
                <p>Your Login Email: {{user.user_email}}</p>
                <p>Your Login Password: <em>password you used during signup</em></p>
                <p>Login URL: {{site.login_url}}</p>
            </blockquote>
            <p>&nbsp;</p>
            <p class="align-center" style="text-align: center;" align="center"><a style="color: #ffffff; background-color: #0072ff; font-size: 16px; border-radius: 5px; text-decoration: none; font-weight: bold; font-style: normal; padding: 0.8rem 1rem; border-color: #0072ff;" href="##site.url##">Visit the Website</a></p>
            <p>&nbsp;</p>
            <p>If you have any questions or need assistance, please don't hesitate to contact us.</p>
            <p>Best regards,<br/>All at {{site.name}}<br/>{{site.url}}</p>
            <?php
            return ob_get_clean();
        }

        return '';

    }

    public static function withHtmlTemplate($body, $footer = null, $wpUser = null)
    {
        $templateConfig = Arr::get(self::getGlobalSettings(), 'template_settings', []);

        if ($footer === null) {
            $footer = Arr::get($templateConfig, 'footer_text', '');
        }

        $html = (string)Helper::loadView('email_template', [
            'body'            => $body,
            'footer'          => $footer,
            'user'            => $wpUser,
            'template_config' => $templateConfig,
        ]);

        return (string)(new Emogrifier($html))->emogrify();
    }

    public static function getEmailFooter()
    {
        $globalSettings = self::getGlobalSettings();
        return Arr::get($globalSettings, 'template_settings.footer_text', '');
    }

}
