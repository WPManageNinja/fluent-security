<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\WPSystemEmailHandler;
use FluentAuth\App\Services\SystemEmailService;

/**
 * The admin's "Password Changed" notice: left alone by default, rewritten when
 * customised, and gone entirely when switched off.
 */
class PasswordChangeAdminEmailTest extends BaseTestCase
{
    private $handler;

    public function setUp(): void
    {
        parent::setUp();
        delete_option('fa_system_email_settings');
        $this->handler = new WPSystemEmailHandler();
    }

    public function tearDown(): void
    {
        delete_option('fa_system_email_settings');
        SystemEmailService::resetStatics();
        parent::tearDown();
    }

    private function setStatus($status, $email = [])
    {
        $settings = SystemEmailService::getGlobalSettings();
        $settings['emails']['password_change_to_admin']['status'] = $status;

        if ($email) {
            $settings['emails']['password_change_to_admin']['email'] = $email;
        }

        update_option('fa_system_email_settings', $settings, false);
        SystemEmailService::resetStatics();
    }

    private function defaults()
    {
        return [
            'to'      => get_option('admin_email'),
            'subject' => '[%s] Password Changed',
            'message' => 'Password changed for user: someone',
            'headers' => '',
        ];
    }

    public function test_it_is_listed_as_an_admin_email_that_can_be_switched_off()
    {
        $indexes = SystemEmailService::getEmailIndexes();

        $this->assertArrayHasKey('password_change_to_admin', $indexes);
        $this->assertEquals('site_admin', $indexes['password_change_to_admin']['recipient']);
        $this->assertEquals('yes', $indexes['password_change_to_admin']['can_disable']);
        $this->assertEquals('system', $indexes['password_change_to_admin']['status']);
    }

    public function test_it_ships_with_a_default_subject_and_body()
    {
        $defaults = SystemEmailService::getEmailDefaults();

        $this->assertArrayHasKey('password_change_to_admin', $defaults);
        $this->assertNotEmpty($defaults['password_change_to_admin']['email']['subject']);
        $this->assertStringContainsString(
            '{{user.user_login}}',
            $defaults['password_change_to_admin']['email']['body']
        );
    }

    public function test_wordpress_default_is_left_untouched()
    {
        $userId = $this->factory->user->create(['user_login' => 'changer']);
        $defaults = $this->defaults();

        $altered = $this->handler->maybeAlterPasswordChangeEmailToAdmin(
            $defaults,
            new \WP_User($userId),
            'Test Site'
        );

        $this->assertEquals($defaults, $altered);
    }

    public function test_a_customised_email_replaces_subject_body_and_headers()
    {
        $userId = $this->factory->user->create(['user_login' => 'changer']);

        $this->setStatus('active', [
            'subject' => 'Heads up about {{user.user_login}}',
            'body'    => '<p>{{user.user_login}} changed their password.</p>',
        ]);

        $altered = $this->handler->maybeAlterPasswordChangeEmailToAdmin(
            $this->defaults(),
            new \WP_User($userId),
            'Test Site'
        );

        $this->assertEquals('Heads up about changer', $altered['subject']);
        $this->assertStringContainsString('changer changed their password.', $altered['message']);
        $this->assertStringContainsString('<html', strtolower($altered['message']));
        $this->assertContains('Content-Type: text/html; charset=UTF-8', $altered['headers']);
    }

    /**
     * Core sprintf()s the site title into whatever subject comes back, so a percent
     * sign an admin typed has to reach the mailbox as a percent sign.
     */
    public function test_a_percent_sign_in_the_subject_survives_cores_sprintf()
    {
        $userId = $this->factory->user->create(['user_login' => 'changer']);

        $this->setStatus('active', [
            'subject' => '100% sure: password changed',
            'body'    => '<p>Body</p>',
        ]);

        $altered = $this->handler->maybeAlterPasswordChangeEmailToAdmin(
            $this->defaults(),
            new \WP_User($userId),
            'Test Site'
        );

        $this->assertEquals('100% sure: password changed', sprintf($altered['subject'], 'Test Site'));
    }

    public function test_switching_it_off_removes_the_core_notification()
    {
        $this->setStatus('disabled');

        $this->handler->register();
        do_action('init');

        $this->assertFalse(has_action('after_password_reset', 'wp_password_change_notification'));
    }

    public function test_it_stays_hooked_while_the_email_is_still_wanted()
    {
        $this->setStatus('active', [
            'subject' => 'Password changed',
            'body'    => '<p>Body</p>',
        ]);

        $this->handler->register();
        do_action('init');

        $this->assertNotFalse(has_action('after_password_reset', 'wp_password_change_notification'));
    }
}
