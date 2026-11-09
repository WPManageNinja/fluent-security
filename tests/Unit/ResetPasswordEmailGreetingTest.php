<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;

/**
 * The reset email FluentAuth's own lost-password form sends greets the person by first
 * name. With no first name on the account it used to read "Hi ,".
 */
class ResetPasswordEmailGreetingTest extends BaseTestCase
{
    private $sent = [];

    public function setUp(): void
    {
        parent::setUp();

        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}fls_auth_logs");

        $formSettings = Helper::getAuthFormsSettings();
        $formSettings['enabled'] = 'yes';
        update_option('__fls_auth_forms_settings', $formSettings);
        Helper::resetStatics();
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    private function resetEmailFor($login)
    {
        $this->sent = [];
        $catch = function ($return, $atts) {
            $this->sent[] = $atts;
            return true;
        };

        $_REQUEST['user_login'] = $login;
        $_REQUEST['_fls_reset_pass_nonce'] = wp_create_nonce('fluent_auth_reset_pass_nonce');

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);
        add_filter('pre_wp_mail', $catch, 10, 2);

        ob_start();
        try {
            (new CustomAuthHandler())->handlePasswordResentAjax();
        } catch (\WPDieException $e) {
            // wp_send_json() ends in wp_die().
        } finally {
            ob_end_clean();
            remove_filter('pre_wp_mail', $catch, 10);
            remove_filter('wp_doing_ajax', '__return_true');
            remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);
            unset($_REQUEST['user_login'], $_REQUEST['_fls_reset_pass_nonce']);
        }

        $this->assertCount(1, $this->sent, 'one reset email was sent');

        return $this->sent[0]['message'];
    }

    public function test_it_greets_by_first_name()
    {
        $this->factory->user->create([
            'user_login'   => 'firstnamed',
            'user_email'   => 'firstnamed@example.test',
            'first_name'   => 'Amira',
            'display_name' => 'Amira K',
        ]);

        $this->assertStringContainsString('Hi Amira,', $this->resetEmailFor('firstnamed'));
    }

    public function test_with_no_first_name_it_greets_by_display_name()
    {
        $this->factory->user->create([
            'user_login'   => 'nofirstname',
            'user_email'   => 'nofirstname@example.test',
            'display_name' => 'Shop Owner',
        ]);

        $message = $this->resetEmailFor('nofirstname');

        $this->assertStringContainsString('Hi Shop Owner,', $message);
        $this->assertStringNotContainsString('Hi ,', $message);
    }

    /**
     * The body is HTML, so a name is printed as text, never as markup.
     */
    public function test_the_name_is_escaped_in_the_html_body()
    {
        global $wpdb;

        $userId = $this->factory->user->create([
            'user_login' => 'markupname',
            'user_email' => 'markupname@example.test',
        ]);
        $wpdb->update($wpdb->users, ['display_name' => '<img src=x onerror=alert(1)>'], ['ID' => $userId]);
        clean_user_cache($userId);

        $message = $this->resetEmailFor('markupname');

        $this->assertStringNotContainsString('<img src=x', $message);
        $this->assertStringContainsString('Hi &lt;img src=x onerror=alert(1)&gt;,', $message);
    }
}
