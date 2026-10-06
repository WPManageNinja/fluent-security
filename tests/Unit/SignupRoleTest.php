<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Services\AuthService;

/**
 * Nobody signs themselves up as an administrator.
 *
 * Every self-service route into an account - the signup shortcode, the signup form on
 * the customized login page, a social login - ends in AuthService::registerNewUser(),
 * and that is where the rule lives. One mistaken pick in Settings > General > New User
 * Default Role, or one filter returning the wrong thing, would otherwise hand the site
 * to whoever registers next.
 */
class SignupRoleTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        wp_set_current_user(0);
        update_option('users_can_register', 1);
        $_SERVER['REMOTE_ADDR'] = '198.51.100.40';
    }

    public function tearDown(): void
    {
        update_option('default_role', 'subscriber');
        remove_all_filters('fluent_auth/user_role');
        remove_all_filters('fluent_auth/signup_default_role');
        remove_all_filters('fluent_auth/verify_signup_email');
        delete_option('__fls_auth_forms_settings');
        unset($_SERVER['REMOTE_ADDR']);
        foreach (['_fls_signup_nonce', 'first_name', 'username', 'email', 'password'] as $key) {
            unset($_REQUEST[$key]);
        }
        wp_set_current_user(0);
        Helper::resetStatics();

        parent::tearDown();
    }

    // ------------------------------------------------------------- the shared rule

    public function test_an_administrator_role_is_never_granted()
    {
        $userId = AuthService::registerNewUser('role_probe_1', 'role_probe_1@example.org', 'secret-pass', [
            'role' => 'administrator'
        ]);

        $this->assertSame(['subscriber'], get_user_by('ID', $userId)->roles);
    }

    /**
     * With no role given, wp_insert_user() falls back to the default_role option on its
     * own - so the option has to be checked here as well, not only by the callers.
     */
    public function test_a_missing_role_does_not_fall_through_to_an_administrator_default()
    {
        update_option('default_role', 'administrator');

        $userId = AuthService::registerNewUser('role_probe_2', 'role_probe_2@example.org', 'secret-pass');

        $this->assertSame(['subscriber'], get_user_by('ID', $userId)->roles);
    }

    public function test_a_role_that_does_not_exist_becomes_a_subscriber()
    {
        $userId = AuthService::registerNewUser('role_probe_3', 'role_probe_3@example.org', 'secret-pass', [
            'role' => 'no_such_role'
        ]);

        $this->assertSame(['subscriber'], get_user_by('ID', $userId)->roles);
    }

    public function test_any_other_role_a_site_chooses_is_kept()
    {
        update_option('default_role', 'editor');

        $userId = AuthService::registerNewUser('role_probe_4', 'role_probe_4@example.org', 'secret-pass');

        $this->assertSame(['editor'], get_user_by('ID', $userId)->roles);
    }

    // ----------------------------------------------------------------- every route

    public function test_a_social_signup_cannot_be_filtered_into_an_administrator()
    {
        add_filter('fluent_auth/user_role', function () {
            return 'administrator';
        });

        $user = AuthService::doUserAuth([
            'email'      => 'role_social@example.org',
            'first_name' => 'Role',
            'last_name'  => 'Social'
        ]);

        $this->assertInstanceOf(\WP_User::class, $user);
        $this->assertSame(['subscriber'], get_user_by('ID', $user->ID)->roles);
    }

    public function test_the_signup_form_cannot_create_an_administrator()
    {
        update_option('default_role', 'administrator');
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes']);
        add_filter('fluent_auth/verify_signup_email', '__return_false');
        Helper::resetStatics();

        $_REQUEST['_fls_signup_nonce'] = wp_create_nonce('fluent_auth_signup_nonce');
        $_REQUEST['first_name'] = 'Role';
        $_REQUEST['username'] = 'role_form';
        $_REQUEST['email'] = 'role_form@example.org';
        $_REQUEST['password'] = 'secret-pass';

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
        ob_end_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', $die);

        $user = get_user_by('login', 'role_form');

        $this->assertInstanceOf(\WP_User::class, $user, 'precondition: the account was created');
        $this->assertSame(['subscriber'], $user->roles);
    }
}
