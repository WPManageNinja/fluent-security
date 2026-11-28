<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\LoginCustomizerHandler;

/**
 * People's names are not policed for characters.
 *
 * Both signup forms used to refuse any name with a hyphen or an apostrophe, so Mary-Jane
 * and O'Brien could not register - and the shortcode form did it silently, returning a
 * string from an ajax handler. WordPress itself only runs sanitize_text_field() over a
 * name. A link is the one thing still refused.
 */
class SignupNameTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        wp_set_current_user(0);
        update_option('users_can_register', 1);
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes']);
        $_SERVER['REMOTE_ADDR'] = '198.51.100.41';
        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/verify_signup_email');
        remove_all_filters('fluent_auth/signup_verification_email_body');
        remove_all_filters('pre_wp_mail');
        delete_option('__fls_auth_forms_settings');
        unset($_SERVER['REMOTE_ADDR']);
        foreach (['_fls_signup_nonce', 'first_name', 'last_name', 'username', 'email', 'password'] as $key) {
            unset($_REQUEST[$key]);
        }
        wp_set_current_user(0);
        Helper::resetStatics();

        parent::tearDown();
    }

    /**
     * Posts the shortcode signup form. Values go in slashed, the way WordPress hands
     * $_REQUEST to a handler.
     *
     * @return array the JSON reply
     */
    private function signup($firstName, $lastName, $login)
    {
        $_REQUEST['_fls_signup_nonce'] = wp_create_nonce('fluent_auth_signup_nonce');
        $_REQUEST['first_name'] = wp_slash($firstName);
        $_REQUEST['last_name'] = wp_slash($lastName);
        $_REQUEST['username'] = $login;
        $_REQUEST['email'] = $login . '@example.org';
        $_REQUEST['password'] = 'secret-pass-123';

        $die = function () {
            return function ($message = '') {
                throw new \WPDieException((string)$message);
            };
        };

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', $die);

        ob_start();
        try {
            (new CustomAuthHandler())->handleSignupAjax();
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', $die);

        return (array)json_decode($output, true);
    }

    public function test_a_hyphen_and_an_apostrophe_are_accepted_and_saved_unslashed()
    {
        add_filter('fluent_auth/verify_signup_email', '__return_false');

        $this->signup("Mary-Jane", "O'Brien", 'name_probe_1');

        $user = get_user_by('login', 'name_probe_1');

        $this->assertInstanceOf(\WP_User::class, $user, 'the account was created');
        $this->assertSame('Mary-Jane', $user->first_name);
        $this->assertSame("O'Brien", $user->last_name);
    }

    public function test_a_link_in_the_name_is_refused_with_a_message()
    {
        add_filter('fluent_auth/verify_signup_email', '__return_false');

        $reply = $this->signup('Visit https://spam.example', 'Now', 'name_probe_2');

        $this->assertSame('Please provide a valid name', $reply['message'] ?? null);
        $this->assertFalse(get_user_by('login', 'name_probe_2'));
    }

    /**
     * With the character list gone, angle brackets reach the verification email - which
     * goes to whatever address the visitor typed. The greeting must carry text only.
     */
    public function test_the_verification_email_greets_with_plain_text_only()
    {
        add_filter('pre_wp_mail', '__return_true');

        $body = '';
        add_filter('fluent_auth/signup_verification_email_body', function ($message) use (&$body) {
            $body = $message;
            return $message;
        });

        (new CustomAuthHandler())->sendSignupEmailVerificationHtml([
            'email'      => 'name_probe_3@example.org',
            'first_name' => wp_slash("O'Brien <a href=\"https://evil.example\">click</a>"),
        ]);

        $this->assertStringContainsString('Hello O&#039;Brien click,', $body);
        $this->assertStringNotContainsString('<a ', $body);
        $this->assertStringNotContainsString('\\', $body);
    }

    public function test_the_login_page_form_accepts_the_same_names()
    {
        $errors = $this->validateRegistration("Mary-Jane O'Brien");

        $this->assertEmpty($errors->get_error_messages('user_full_name'));
    }

    public function test_the_login_page_form_refuses_a_link()
    {
        $errors = $this->validateRegistration('http://spam.example');

        $this->assertSame(['Please provide a valid name.'], $errors->get_error_messages('user_full_name'));
    }

    /**
     * @return \WP_Error
     */
    private function validateRegistration($fullName)
    {
        $method = new \ReflectionMethod(LoginCustomizerHandler::class, 'validateRegistrationData');

        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }

        return $method->invoke(new LoginCustomizerHandler(), [
            'user_full_name'        => wp_slash($fullName),
            'user_password'         => 'secret-pass-123',
            'user_confirm_password' => 'secret-pass-123',
            'agree_terms'           => 'yes',
        ]);
    }
}
