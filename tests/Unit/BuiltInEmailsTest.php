<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SystemEmailsController;
use FluentAuth\App\Services\BuiltInEmails;
use FluentAuth\App\Services\SystemEmailService;

/**
 * The editor shows what an email says when it is left on Built-in, so an owner can decide
 * whether to write their own without having to trigger the email to find out.
 */
class BuiltInEmailsTest extends BaseTestCase
{
    private $admin;

    public function setUp(): void
    {
        parent::setUp();
        delete_option('fa_system_email_settings');
        SystemEmailService::resetStatics();

        $this->admin = self::factory()->user->create_and_get([
            'role'         => 'administrator',
            'user_login'   => 'site-owner',
            'user_email'   => 'owner@example.test',
            'display_name' => 'Site Owner',
        ]);
        wp_set_current_user($this->admin->ID);
    }

    public function test_every_email_on_the_list_has_a_built_in_preview()
    {
        foreach (array_keys(SystemEmailService::getEmailIndexes()) as $emailId) {
            $preview = BuiltInEmails::preview($emailId, $this->admin);

            $this->assertIsArray($preview, $emailId);
            $this->assertContains($preview['format'], ['html', 'text', 'none'], $emailId);
            $this->assertNotSame('', trim($preview['body']), $emailId);
        }
    }

    public function test_wordpress_emails_are_plain_text_with_the_admins_details()
    {
        $reset = BuiltInEmails::preview('password_reset_to_user', $this->admin);

        $this->assertSame('text', $reset['format']);
        $this->assertStringContainsString('Password Reset', $reset['subject']);
        $this->assertStringContainsString('Username: site-owner', $reset['body']);
        $this->assertStringContainsString('action=rp', $reset['body']);

        $changed = BuiltInEmails::preview('email_change_notification_after_confimation', $this->admin);
        $this->assertStringContainsString('Hi site-owner,', $changed['body']);
        $this->assertStringNotContainsString('###', $changed['body']);

        $request = BuiltInEmails::preview('email_change_notification_to_user', $this->admin);
        $this->assertStringContainsString('Howdy site-owner,', $request['body']);
        $this->assertStringNotContainsString('###', $request['body']);
    }

    /**
     * Core reworded the set-password email: 7.0 dropped the trailing login URL, 7.1 the
     * username line. The preview has to show the one this site actually sends.
     */
    public function test_the_login_details_email_follows_the_installed_wordpress()
    {
        global $wp_version;
        $real = $wp_version;
        $login = wp_login_url();

        try {
            $wp_version = '6.9.4';
            $body = BuiltInEmails::preview('user_registration_to_user', $this->admin)['body'];
            $this->assertStringStartsWith('Username: site-owner', $body);
            $this->assertStringEndsWith($login . "\r\n", $body);

            $wp_version = '7.0';
            $body = BuiltInEmails::preview('user_registration_to_user', $this->admin)['body'];
            $this->assertStringStartsWith('Username: site-owner', $body);
            $this->assertStringNotContainsString("\r\n" . $login . "\r\n", $body);

            $wp_version = '7.1.5';
            $body = BuiltInEmails::preview('user_registration_to_user', $this->admin)['body'];
            $this->assertStringStartsWith('To set your password', $body);
        } finally {
            $wp_version = $real;
        }
    }

    public function test_the_reset_preview_shows_the_requester_ip_line()
    {
        $body = BuiltInEmails::preview('password_reset_to_user', $this->admin)['body'];

        $this->assertStringContainsString('originated from the IP address 192.0.2.10.', $body);
    }

    public function test_fluentauth_emails_are_the_same_html_that_is_sent()
    {
        $preview = BuiltInEmails::preview('two_fa_email_to_user', $this->admin);
        $sent = BuiltInEmails::twoFaCode($this->admin, '123456', home_url('/'), 10);

        $this->assertSame('html', $preview['format']);
        $this->assertSame($sent['subject'], $preview['subject']);
        $this->assertSame($sent['body'], $preview['body']);
        $this->assertStringContainsString('123456', $preview['body']);
    }

    public function test_welcome_shows_the_default_welcome_while_the_registration_email_is_customised()
    {
        $this->assertSame('text', BuiltInEmails::preview('fluent_auth_welcome_email_to_user', $this->admin)['format']);

        update_option('fa_system_email_settings', ['emails' => [
            'user_registration_to_user' => ['status' => 'active', 'email' => ['subject' => 'Hi', 'body' => '<p>Set it</p>']],
        ]]);
        SystemEmailService::resetStatics();

        $preview = BuiltInEmails::preview('fluent_auth_welcome_email_to_user', $this->admin);
        $this->assertSame('html', $preview['format']);
        $this->assertStringNotContainsString('{{', $preview['subject'] . $preview['body']);
        $this->assertStringContainsString('Site Owner', $preview['body']);
    }

    public function test_the_editor_receives_the_built_in_email()
    {
        $request = new \WP_REST_Request('GET', '/fluent-auth/wp-default-emails/find-email');
        $request->set_param('email_id', 'magic_email_to_user');

        $result = SystemEmailsController::findEmail($request);

        $this->assertIsArray($result);
        $this->assertSame('html', $result['built_in']['format']);
        $this->assertStringContainsString('Site Owner', $result['built_in']['body']);
    }
}
