<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\TurnstileHandler;
use FluentAuth\App\Http\Controllers\TurnstileController;
use FluentAuth\App\Services\Turnstile;

/**
 * Turnstile on the forms a bot uses to make the site send email.
 *
 * Cloudflare is never called: pre_http_request answers for it. Each test sets what
 * Cloudflare says, or that it cannot be reached.
 */
class TurnstileTest extends BaseTestCase
{
    /** @var array|\WP_Error|null what Siteverify answers; null means it is not called */
    private $siteverify = null;

    /** @var int how many times Siteverify was called */
    private $verifyCalls = 0;

    /** @var int how many emails were sent */
    private $mails = 0;

    public function setUp(): void
    {
        parent::setUp();

        wp_set_current_user(0);
        update_option('users_can_register', 1);
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes']);
        $_SERVER['REMOTE_ADDR'] = '198.51.100.77';
        Helper::resetStatics();

        $this->siteverify = null;
        $this->verifyCalls = 0;
        $this->mails = 0;

        add_filter('pre_http_request', [$this, 'fakeCloudflare'], 10, 3);
        add_filter('pre_wp_mail', [$this, 'countMail']);
    }

    public function tearDown(): void
    {
        remove_filter('pre_http_request', [$this, 'fakeCloudflare'], 10);
        remove_filter('pre_wp_mail', [$this, 'countMail']);
        remove_all_filters('fluent_auth/verify_signup_email');
        delete_option(Turnstile::OPTION);
        delete_option('__fls_auth_forms_settings');
        delete_option('_fluentform_turnstile_details');
        delete_option('fluent_cart_modules_settings');
        delete_option('__fls_auth_settings');
        unset($_SERVER['REMOTE_ADDR']);
        $_POST = [];
        $_REQUEST = [];
        wp_dequeue_script('fluent_auth_turnstile');
        wp_deregister_script('fluent_auth_turnstile');
        Helper::resetStatics();

        parent::tearDown();
    }

    public function fakeCloudflare($pre, $args, $url)
    {
        if ($url !== Turnstile::VERIFY_URL) {
            return $pre;
        }

        $this->verifyCalls++;

        if ($this->siteverify === null) {
            $this->fail('Siteverify was called when it should not have been');
        }

        return $this->siteverify;
    }

    public function countMail()
    {
        $this->mails++;
        return true;
    }

    private function cloudflareSays($body, $code = 200)
    {
        $this->siteverify = [
            'headers'  => [],
            'body'     => is_string($body) ? $body : wp_json_encode($body),
            'response' => ['code' => $code, 'message' => 'OK'],
            'cookies'  => []
        ];
    }

    private function guard($places = ['signup', 'login', 'woo'])
    {
        $settings = ['site_key' => '0x-site', 'secret_key' => '0x-secret'];

        foreach ($places as $place) {
            $settings[$place] = 'yes';
        }

        update_option(Turnstile::OPTION, $settings);
    }

    private function sendToken($token = 'browser-token')
    {
        $_POST[Turnstile::RESPONSE_FIELD] = $token;
        $_REQUEST[Turnstile::RESPONSE_FIELD] = $token;
    }

    /**
     * Runs an ajax handler and returns its JSON reply.
     */
    private function ajax(callable $handler)
    {
        $die = function () {
            return function ($message = '') {
                throw new \WPDieException((string)$message);
            };
        };

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('wp_die_ajax_handler', $die);

        ob_start();
        try {
            $handler();
        } catch (\WPDieException $e) {
            // wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', $die);

        return (array)json_decode($output, true);
    }

    /* ---------------------------------------------------------------- verify() */

    public function test_a_missing_token_is_refused_without_asking_cloudflare()
    {
        $this->assertWpErrorWithCode(Turnstile::verify('', 'secret'), 'fls_turnstile_failed');
        $this->assertSame(0, $this->verifyCalls);
    }

    public function test_a_token_cloudflare_accepts_passes()
    {
        $this->cloudflareSays(['success' => true]);

        $this->assertTrue(Turnstile::verify('token', 'secret'));
    }

    public function test_a_token_cloudflare_rejects_is_refused()
    {
        foreach (['invalid-input-response', 'timeout-or-duplicate'] as $code) {
            $this->cloudflareSays(['success' => false, 'error-codes' => [$code]]);

            $this->assertWpErrorWithCode(Turnstile::verify('token', 'secret'), 'fls_turnstile_failed', $code);
        }
    }

    /**
     * An outage or a rotated secret key must not stop every password login on the site.
     */
    public function test_cloudflare_trouble_and_a_bad_secret_let_the_form_through()
    {
        $this->siteverify = new \WP_Error('http_request_failed', 'timed out');
        $this->assertTrue(Turnstile::verify('token', 'secret'), 'unreachable');

        $this->cloudflareSays('<html>bad gateway</html>', 502);
        $this->assertTrue(Turnstile::verify('token', 'secret'), '5xx');

        $this->cloudflareSays('not json');
        $this->assertTrue(Turnstile::verify('token', 'secret'), 'garbage');

        $this->cloudflareSays(['success' => false, 'error-codes' => ['invalid-input-secret']]);
        $this->assertTrue(Turnstile::verify('token', 'secret'), 'secret rotated');

        $this->cloudflareSays(['success' => false, 'error-codes' => ['internal-error']]);
        $this->assertTrue(Turnstile::verify('token', 'secret'), 'internal error');
    }

    /* ----------------------------------------------------- settings and widget */

    public function test_a_place_is_guarded_only_with_both_keys_and_its_switch_on()
    {
        $this->assertFalse(Turnstile::isActive(Turnstile::SIGNUP), 'nothing saved');

        update_option(Turnstile::OPTION, ['site_key' => 'site', 'secret_key' => '', 'signup' => 'yes']);
        $this->assertFalse(Turnstile::isActive(Turnstile::SIGNUP), 'no secret');

        $this->guard(['signup']);
        $this->assertTrue(Turnstile::isActive(Turnstile::SIGNUP));
        $this->assertFalse(Turnstile::isActive(Turnstile::LOGIN));
    }

    public function test_the_woocommerce_place_needs_woocommerce()
    {
        $this->guard(['woo']);

        $this->assertSame(class_exists('WooCommerce'), Turnstile::isActive(Turnstile::WOO));
    }

    public function test_the_widget_renders_and_queues_the_script_only_where_guarded()
    {
        $this->assertSame('', Turnstile::widget(Turnstile::SIGNUP));
        $this->assertFalse(wp_script_is('fluent_auth_turnstile', 'enqueued'));

        $this->guard(['signup']);

        $html = Turnstile::widget(Turnstile::SIGNUP);

        $this->assertStringContainsString('class="fls_turnstile cf-turnstile"', $html);
        $this->assertStringContainsString('data-sitekey="0x-site"', $html);
        $this->assertTrue(wp_script_is('fluent_auth_turnstile', 'enqueued'));
    }

    public function test_the_signup_shortcode_carries_the_widget()
    {
        $this->guard(['signup']);

        $html = (new CustomAuthHandler())->registrationForm([]);

        $this->assertStringContainsString('cf-turnstile', $html);
    }

    public function test_wp_login_form_carries_the_widget_when_login_is_guarded()
    {
        $this->guard(['login']);

        $this->assertStringContainsString('cf-turnstile', wp_login_form(['echo' => false]));
    }

    /* ------------------------------------------------------------ wp-login.php */

    public function test_a_password_login_on_wp_login_needs_a_token()
    {
        $this->guard(['login']);
        do_action('login_form_login');
        $_POST['log'] = 'someone';

        $user = self::factory()->user->create_and_get();

        $this->assertWpErrorWithCode((new TurnstileHandler())->checkLogin($user), 'fls_turnstile_failed');

        $this->cloudflareSays(['success' => true]);
        $this->sendToken();

        $this->assertSame($user, (new TurnstileHandler())->checkLogin($user));
    }

    /**
     * XML-RPC, Application Passwords and other plugins' wp_signon() calls go through
     * `authenticate` too, and none of them has a widget.
     */
    public function test_a_login_that_is_not_the_wp_login_form_is_left_alone()
    {
        $this->guard(['login']);
        $_POST['log'] = 'someone';

        $user = self::factory()->user->create_and_get();

        $this->assertSame($user, (new TurnstileHandler())->checkLogin($user));
    }

    public function test_the_wp_login_lost_password_form_needs_a_token()
    {
        $this->guard(['login']);
        do_action('login_form_lostpassword');

        $errors = new \WP_Error();
        (new TurnstileHandler())->checkLostPassword($errors);

        $this->assertContains('fls_turnstile_failed', $errors->get_error_codes());
    }

    /**
     * retrieve_password() fires `lostpassword_post` for the Users screen's "Send password
     * reset" too.
     */
    public function test_an_administrator_sending_a_reset_link_is_not_stopped()
    {
        $this->guard(['login']);

        $user = self::factory()->user->create_and_get();

        $this->assertTrue(retrieve_password($user->user_login));
        $this->assertSame(1, $this->mails);
    }

    public function test_wp_login_registration_needs_a_token_and_sends_nothing_without_one()
    {
        $this->guard(['signup']);
        do_action('login_form_register');

        $result = register_new_user('ts_bot', 'ts_bot@example.org');

        $this->assertWPError($result);
        $this->assertContains('fls_turnstile_failed', $result->get_error_codes());
        $this->assertFalse(get_user_by('login', 'ts_bot'));
        $this->assertSame(0, $this->mails);
    }

    public function test_secure_signup_code_step_skips_the_widget()
    {
        $this->guard(['signup']);
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), ['secure_signup_form' => 'yes']));
        Helper::resetStatics();
        do_action('login_form_register');
        $_POST['_email_verification_hash'] = 'some-hash';

        $errors = new \WP_Error();
        (new TurnstileHandler())->checkRegistration('ts_user', 'ts_user@example.org', $errors);

        $this->assertNotContains('fls_turnstile_failed', $errors->get_error_codes());
    }

    /**
     * Without the secure form nothing checks the code, so a made-up hash must not skip
     * the widget.
     */
    public function test_a_made_up_code_hash_does_not_skip_the_widget_without_secure_signup()
    {
        $this->guard(['signup']);
        update_option('__fls_auth_settings', array_merge(Helper::getAuthSettings(), ['secure_signup_form' => 'no']));
        Helper::resetStatics();
        do_action('login_form_register');
        $_POST['_email_verification_hash'] = 'made-up';

        $errors = new \WP_Error();
        (new TurnstileHandler())->checkRegistration('ts_user', 'ts_user@example.org', $errors);

        $this->assertContains('fls_turnstile_failed', $errors->get_error_codes());
    }

    /* ------------------------------------------------------------- WooCommerce */

    public function test_woocommerce_account_forms_need_a_token()
    {
        if (!class_exists('WooCommerce')) {
            eval('class WooCommerce {}');
        }

        $this->guard(['woo']);

        $errors = (new TurnstileHandler())->checkWooForm(new \WP_Error());
        $this->assertContains('fls_turnstile_failed', $errors->get_error_codes());

        $this->cloudflareSays(['success' => true]);
        $this->sendToken();

        $errors = (new TurnstileHandler())->checkWooForm(new \WP_Error());
        $this->assertFalse($errors->has_errors());
    }

    /* -------------------------------------------------------- shortcode ajax */

    private function signupRequest($login)
    {
        $_REQUEST['_fls_signup_nonce'] = wp_create_nonce('fluent_auth_signup_nonce');
        $_REQUEST['first_name'] = 'Test';
        $_REQUEST['last_name'] = 'Person';
        $_REQUEST['username'] = $login;
        $_REQUEST['email'] = $login . '@example.org';
        $_REQUEST['password'] = 'secret-pass-123';
        $_REQUEST['agree_terms'] = 'agreed';
    }

    public function test_the_signup_shortcode_refuses_without_a_token_and_sends_no_code()
    {
        $this->guard(['signup']);
        $this->signupRequest('ts_short_1');

        $reply = $this->ajax(function () {
            (new CustomAuthHandler())->handleSignupAjax();
        });

        $this->assertSame('Please complete the security check and try again.', $reply['message'] ?? null);
        $this->assertSame(0, $this->mails);
    }

    public function test_the_signup_shortcode_sends_the_code_once_the_token_passes()
    {
        $this->guard(['signup']);
        $this->signupRequest('ts_short_2');
        $this->cloudflareSays(['success' => true]);
        $this->sendToken();

        $reply = $this->ajax(function () {
            (new CustomAuthHandler())->handleSignupAjax();
        });

        $this->assertArrayHasKey('verifcation_html', $reply);
        $this->assertSame(1, $this->mails);
    }

    public function test_the_signup_code_step_is_proven_by_the_code_not_the_widget()
    {
        $this->guard(['signup']);
        $this->signupRequest('ts_short_3');
        $_REQUEST['_email_verification_token'] = '123456';
        $_REQUEST['_email_verification_hash'] = 'made-up';

        $reply = $this->ajax(function () {
            (new CustomAuthHandler())->handleSignupAjax();
        });

        $this->assertNotSame('Please complete the security check and try again.', $reply['message'] ?? null);
        $this->assertFalse(get_user_by('login', 'ts_short_3'));
    }

    public function test_a_made_up_code_does_not_skip_the_widget_when_verification_is_off()
    {
        add_filter('fluent_auth/verify_signup_email', '__return_false');
        $this->guard(['signup']);
        $this->signupRequest('ts_short_4');
        $_REQUEST['_email_verification_token'] = '123456';

        $reply = $this->ajax(function () {
            (new CustomAuthHandler())->handleSignupAjax();
        });

        $this->assertSame('Please complete the security check and try again.', $reply['message'] ?? null);
        $this->assertFalse(get_user_by('login', 'ts_short_4'));
    }

    public function test_the_login_shortcode_refuses_without_a_token()
    {
        $this->guard(['login']);
        $user = self::factory()->user->create_and_get(['user_pass' => 'right-pass']);

        $_REQUEST['_nonce'] = wp_create_nonce('fsecurity_login_nonce');
        $_REQUEST['_is_fls_form'] = 'yes';
        $_REQUEST['log'] = $user->user_login;
        $_REQUEST['pwd'] = 'right-pass';
        $_POST = $_REQUEST;

        $reply = $this->ajax(function () {
            (new CustomAuthHandler())->handleLoginAjax();
        });

        $this->assertSame('Please complete the security check and try again.', $reply['message'] ?? null);
        $this->assertSame(0, get_current_user_id());
    }

    public function test_the_reset_shortcode_refuses_without_a_token_and_sends_nothing()
    {
        $this->guard(['login']);
        $user = self::factory()->user->create_and_get();

        $_REQUEST['_fls_reset_pass_nonce'] = wp_create_nonce('fluent_auth_reset_pass_nonce');
        $_REQUEST['user_login'] = $user->user_login;

        $reply = $this->ajax(function () {
            (new CustomAuthHandler())->handlePasswordResentAjax();
        });

        $this->assertSame('Please complete the security check and try again.', $reply['message'] ?? null);
        $this->assertSame(0, $this->mails);
    }

    public function test_unguarded_forms_never_call_cloudflare()
    {
        $user = self::factory()->user->create_and_get();

        $_REQUEST['_fls_reset_pass_nonce'] = wp_create_nonce('fluent_auth_reset_pass_nonce');
        $_REQUEST['user_login'] = $user->user_login;

        $this->ajax(function () {
            (new CustomAuthHandler())->handlePasswordResentAjax();
        });

        $this->assertSame(0, $this->verifyCalls);
        $this->assertSame(1, $this->mails);
    }

    /* --------------------------------------------------------------- settings */

    private function save($settings, $token = '')
    {
        $request = new \WP_REST_Request('POST', '/fluent-auth/turnstile');
        $request->set_body_params(['settings' => $settings, 'token' => $token]);

        return TurnstileController::saveSettings($request);
    }

    public function test_new_keys_are_not_saved_without_a_passing_test()
    {
        $result = $this->save(['site_key' => 'new-site', 'secret_key' => 'new-secret', 'login' => 'yes']);

        $this->assertWpErrorWithCode($result, 'turnstile_no_token');
        $this->assertSame('', Turnstile::getSettings()['site_key']);

        $this->cloudflareSays(['success' => false, 'error-codes' => ['invalid-input-secret']]);
        $result = $this->save(['site_key' => 'new-site', 'secret_key' => 'new-secret'], 'token');

        $this->assertWpErrorWithCode($result, 'turnstile_invalid_keys');
        $this->assertSame('', Turnstile::getSettings()['site_key']);
    }

    public function test_keys_that_pass_the_test_are_saved_with_the_switches()
    {
        $this->cloudflareSays(['success' => true]);

        $result = $this->save(['site_key' => ' new-site ', 'secret_key' => 'new-secret', 'signup' => 'yes', 'login' => 'true'], 'token');

        $this->assertIsArray($result);
        $saved = Turnstile::getSettings();
        $this->assertSame('new-site', $saved['site_key']);
        $this->assertSame('yes', $saved['signup']);
        $this->assertSame('no', $saved['login'], 'only "yes" turns a place on');
    }

    public function test_changing_only_the_switches_needs_no_new_test()
    {
        $this->guard([]);

        $result = $this->save(['site_key' => '0x-site', 'secret_key' => '0x-secret', 'woo' => 'yes']);

        $this->assertIsArray($result);
        $this->assertSame('yes', Turnstile::getSettings()['woo']);
        $this->assertSame(0, $this->verifyCalls);
    }

    public function test_one_key_alone_is_refused_and_clearing_both_is_allowed()
    {
        $this->assertWpErrorWithCode($this->save(['site_key' => 'only-site', 'secret_key' => '']), 'turnstile_missing_key');

        $this->guard(['login']);
        $result = $this->save(['site_key' => '', 'secret_key' => '', 'login' => 'yes']);

        $this->assertIsArray($result);
        $this->assertFalse(Turnstile::isActive(Turnstile::LOGIN));
    }

    public function test_keys_from_fluent_forms_and_fluentcart_are_offered()
    {
        $this->assertSame([], Turnstile::getKeySources());

        update_option('_fluentform_turnstile_details', ['siteKey' => 'ff-site', 'secretKey' => 'ff-secret']);
        update_option('fluent_cart_modules_settings', ['turnstile' => ['active' => 'no', 'site_key' => 'fc-site', 'secret_key' => 'fc-secret']]);

        $sources = Turnstile::getKeySources();

        $this->assertSame(['fluentform', 'fluent-cart'], array_column($sources, 'key'));
        $this->assertSame('ff-secret', $sources[0]['secret_key']);
        $this->assertSame('fc-site', $sources[1]['site_key']);
    }

    public function test_open_signup_counts_until_it_is_guarded()
    {
        update_option('users_can_register', 1);
        $this->assertSame(['wordpress'], Turnstile::unguardedSignups());

        $this->guard(['login']);
        $this->assertSame(['wordpress'], Turnstile::unguardedSignups(), 'guarding login does not cover signup');

        $this->guard(['signup']);
        $this->assertSame([], Turnstile::unguardedSignups());

        delete_option(Turnstile::OPTION);
        update_option('users_can_register', 0);
        $this->assertSame([], Turnstile::unguardedSignups(), 'closed signup needs nothing');
    }

    public function test_woocommerce_signup_counts_only_when_its_my_account_form_is_open()
    {
        if (!class_exists('WooCommerce')) {
            eval('class WooCommerce {}');
        }

        update_option('users_can_register', 0);
        update_option('woocommerce_enable_myaccount_registration', 'no');
        $this->assertSame([], Turnstile::unguardedSignups());

        update_option('woocommerce_enable_myaccount_registration', 'yes');
        $this->assertSame(['woocommerce'], Turnstile::unguardedSignups());

        $this->guard(['woo']);
        $this->assertSame([], Turnstile::unguardedSignups());

        delete_option('woocommerce_enable_myaccount_registration');
    }

    private function signupFinding()
    {
        $findings = (new \FluentAuth\App\Services\Checks\Login\SignupBotCheck())->run();

        return $findings ? $findings[0]->toArray() : null;
    }

    public function test_open_signup_without_turnstile_is_recommended_not_flagged()
    {
        update_option('users_can_register', 1);

        $finding = $this->signupFinding();

        $this->assertSame('open', $finding['state']);
        $this->assertSame('advice', $finding['severity'], 'a recommendation, never a fault');
        $this->assertFalse($finding['scored']);
        $this->assertSame('settings_bot_protection', $finding['route']);
    }

    public function test_guarded_signup_passes_and_closed_signup_says_nothing()
    {
        update_option('users_can_register', 1);
        $this->guard(['signup']);
        $this->assertSame('passed', $this->signupFinding()['state']);

        update_option('users_can_register', 0);
        $this->assertNull($this->signupFinding());
    }

    public function test_the_signup_recommendation_can_be_dismissed_and_brought_back()
    {
        update_option('users_can_register', 1);
        $check = new \FluentAuth\App\Services\Checks\Login\SignupBotCheck();

        $check->accept('signup_bot_protection');
        $this->assertSame('accepted', $this->signupFinding()['state']);

        $check->unaccept('signup_bot_protection');
        $this->assertSame('open', $this->signupFinding()['state']);
    }

    public function test_a_source_missing_a_key_is_not_offered()
    {
        update_option('_fluentform_turnstile_details', ['siteKey' => 'ff-site', 'secretKey' => '']);

        $this->assertSame([], Turnstile::getKeySources());
    }
}
