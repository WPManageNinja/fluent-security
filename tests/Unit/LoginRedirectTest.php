<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\MagicLoginHandler;
use FluentAuth\App\Hooks\Handlers\PasskeyLoginHandler;
use FluentAuth\App\Hooks\Handlers\ServerModeHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\AuthService;
use FluentAuth\App\Services\TwoFa\TwoFaService;

/**
 * Where a browser is sent once it has signed in.
 *
 * The AJAX flows answer with a URL that login_helper.js assigns straight to
 * window.location, so nothing like wp_safe_redirect() stands between the reply and the
 * navigation. Any of them handing back an off-site address is an open redirect at the
 * one moment the visitor most trusts the page - they have just typed their password.
 *
 * The path that was open: a logged-out visit to any URL carrying `?redirect_to=` stores
 * it in the `_fls_redirect_to` cookie, and the `login_redirect` filter used to keep that
 * value whenever it failed validation.
 */
class LoginRedirectTest extends BaseTestCase
{
    const OFF_SITE = 'https://evil.example/phish';

    public function setUp(): void
    {
        parent::setUp();

        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        update_option('__fls_auth_forms_settings', ['enabled' => 'yes']);
        Helper::resetStatics();

        $_SERVER['REMOTE_ADDR'] = '198.51.100.30';
    }

    public function tearDown(): void
    {
        unset(
            $_COOKIE['_fls_redirect_to'],
            $_REQUEST['_nonce'], $_REQUEST['_is_fls_form'], $_REQUEST['log'], $_REQUEST['pwd'], $_REQUEST['redirect_to'],
            $_POST['log'], $_POST['pwd'], $_POST['redirect_to'], $_GET['redirect_to'],
            $_REQUEST['login_hash']
        );
        unset($_SERVER['REMOTE_ADDR']);

        remove_all_filters('allowed_redirect_hosts');
        remove_filter('login_redirect', [$this, 'sendOffSite'], 1000);
        delete_option('__fls_auth_forms_settings');
        wp_set_current_user(0);
        Helper::resetStatics();

        parent::tearDown();
    }

    public function sendOffSite()
    {
        return self::OFF_SITE;
    }

    // ------------------------------------------------------------ the filter itself

    public function test_an_off_site_cookie_is_ignored_by_the_login_redirect_filter()
    {
        $user = $this->makeUser('subscriber');
        $_COOKIE['_fls_redirect_to'] = self::OFF_SITE;

        $redirect = apply_filters('login_redirect', home_url('/account/'), '', $user);

        $this->assertSame(home_url('/account/'), $redirect);
    }

    public function test_a_same_site_cookie_still_decides_where_they_land()
    {
        $user = $this->makeUser('subscriber');
        $_COOKIE['_fls_redirect_to'] = home_url('/checkout/');

        $redirect = apply_filters('login_redirect', admin_url(), '', $user);

        $this->assertSame(home_url('/checkout/'), $redirect);
    }

    public function test_an_off_site_cookie_does_not_displace_the_role_redirect()
    {
        $this->setLoginRedirect(home_url('/members/'));

        $user = $this->makeUser('subscriber');
        $_COOKIE['_fls_redirect_to'] = self::OFF_SITE;

        $redirect = apply_filters('login_redirect', admin_url(), '', $user);

        $this->assertSame(home_url('/members/'), $redirect);
    }

    // ---------------------------------------------------------- the AJAX login reply

    public function test_the_ajax_login_reply_never_points_off_site_from_a_planted_cookie()
    {
        $this->makeUser('subscriber', 'redirect_probe');
        $_COOKIE['_fls_redirect_to'] = self::OFF_SITE;

        $reply = $this->loginReply('redirect_probe');

        $this->assertArrayHasKey('redirect', $reply);
        $this->assertSame('example.org', wp_parse_url($reply['redirect'], PHP_URL_HOST));
    }

    /**
     * Core's wp-login.php survives any plugin's `login_redirect` filter because it
     * finishes with wp_safe_redirect(). The JSON reply has no such step unless we add one.
     */
    public function test_the_ajax_login_reply_clamps_another_plugins_off_site_redirect()
    {
        $this->makeUser('subscriber', 'redirect_probe');
        add_filter('login_redirect', [$this, 'sendOffSite'], 1000);

        $reply = $this->loginReply('redirect_probe');

        $this->assertSame(admin_url(), $reply['redirect']);
    }

    /**
     * The settings screen refuses an off-site address now, but one saved before that is
     * still in the option. It is not trusted for having been typed in there.
     */
    public function test_an_off_site_address_saved_in_the_settings_is_not_followed()
    {
        $this->setLoginRedirect('https://shop.example.net/welcome/');
        $this->makeUser('subscriber', 'redirect_probe');

        $reply = $this->loginReply('redirect_probe');

        $this->assertSame(admin_url(), $reply['redirect']);
    }

    public function test_a_host_allowed_through_core_filter_is_respected()
    {
        add_filter('allowed_redirect_hosts', function ($hosts) {
            $hosts[] = 'partner.example.net';
            return $hosts;
        });

        $this->makeUser('subscriber', 'redirect_probe');
        $_COOKIE['_fls_redirect_to'] = 'https://partner.example.net/landing/';

        $reply = $this->loginReply('redirect_probe');

        $this->assertSame('https://partner.example.net/landing/', $reply['redirect']);
    }

    // ------------------------------------------------------------ the other replies

    public function test_the_two_factor_redirect_reply_is_clamped()
    {
        $user = $this->makeUser('subscriber');
        wp_set_current_user($user->ID);

        $useTypes = TwoFaService::getAllUseTypes();

        flsDb()->table('fls_login_hashes')->insert([
            'login_hash'      => 'redirect-probe-hash',
            'user_id'         => $user->ID,
            'status'          => 'used',
            'use_type'        => reset($useTypes),
            'redirect_intend' => home_url('/account/'),
            'created_at'      => current_time('mysql'),
            'updated_at'      => current_time('mysql')
        ]);

        $_REQUEST['login_hash'] = 'redirect-probe-hash';
        $_COOKIE['_fls_redirect_to'] = self::OFF_SITE;

        $reply = $this->captureJson(function () {
            (new TwoFaHandler())->reportChallengeRedirect();
        });

        $this->assertSame(home_url('/account/'), $reply['redirect']);
    }

    /**
     * The row's own destination is on the site; it is another plugin's filter that sends
     * the reply off it, so only the final check can catch this.
     */
    public function test_the_two_factor_redirect_reply_is_clamped_after_the_filters()
    {
        $user = $this->makeUser('subscriber');
        wp_set_current_user($user->ID);

        $useTypes = TwoFaService::getAllUseTypes();

        flsDb()->table('fls_login_hashes')->insert([
            'login_hash'      => 'redirect-probe-hash-2',
            'user_id'         => $user->ID,
            'status'          => 'used',
            'use_type'        => reset($useTypes),
            'redirect_intend' => home_url('/account/'),
            'created_at'      => current_time('mysql'),
            'updated_at'      => current_time('mysql')
        ]);

        $_REQUEST['login_hash'] = 'redirect-probe-hash-2';
        add_filter('login_redirect', [$this, 'sendOffSite'], 1000);

        $reply = $this->captureJson(function () {
            (new TwoFaHandler())->reportChallengeRedirect();
        });

        $this->assertSame(admin_url(), $reply['redirect']);
    }

    public function test_the_signup_reply_is_clamped_after_its_last_filter()
    {
        update_option('users_can_register', 1);
        update_option('default_role', 'subscriber');
        add_filter('fluent_auth/verify_signup_email', '__return_false');
        $offSite = function ($response) {
            $response['redirect'] = self::OFF_SITE;
            return $response;
        };
        add_filter('fluent_auth/signup_complete_response', $offSite);

        $_REQUEST['_fls_signup_nonce'] = wp_create_nonce('fluent_auth_signup_nonce');
        $_REQUEST['first_name'] = 'Redirect';
        $_REQUEST['username'] = 'redirect_signup';
        $_REQUEST['email'] = 'redirect_signup@example.org';
        $_REQUEST['password'] = 'secret-pass';

        try {
            $reply = $this->captureJson(function () {
                (new CustomAuthHandler())->handleSignupAjax();
            });
        } finally {
            remove_filter('fluent_auth/signup_complete_response', $offSite);
            remove_all_filters('fluent_auth/verify_signup_email');
            unset($_REQUEST['_fls_signup_nonce'], $_REQUEST['first_name'], $_REQUEST['username'], $_REQUEST['email'], $_REQUEST['password']);
        }

        $this->assertSame(admin_url(), $reply['redirect']);
    }

    // --------------------------------------------------- the social intent cookie

    public function test_an_off_site_social_intent_is_dropped()
    {
        $_COOKIE['fs_intent_redirect'] = self::OFF_SITE;

        try {
            $this->assertSame('', AuthService::getIntentRedirect());
        } finally {
            unset($_COOKIE['fs_intent_redirect']);
        }
    }

    /**
     * PHP hands $_COOKIE over already decoded; a second decode turned `%2B` into `+` and
     * split encoded parameters apart.
     */
    public function test_a_social_intent_keeps_its_encoded_query_intact()
    {
        $intended = home_url('/finish/?token=abc%2Bdef&next=%2Fa%3Fb%3D1');
        $_COOKIE['fs_intent_redirect'] = $intended;

        try {
            $this->assertSame($intended, AuthService::getIntentRedirect());
        } finally {
            unset($_COOKIE['fs_intent_redirect']);
        }
    }

    // ------------------------------------------------------ server mode child sites

    public function test_a_connected_child_sites_callback_host_is_trusted()
    {
        update_option('__fls_child_sites', [
            'abc' => [
                'site_url'     => 'https://child.example.net',
                'callback_url' => 'https://sso.child-cdn.example.com/callback'
            ]
        ]);

        $handler = new ServerModeHandler();

        try {
            $callback = 'https://sso.child-cdn.example.com/callback?fluent_auth_token=x';
            $this->assertSame($callback, $handler->trustChildSiteHosts(admin_url(), $callback));
            $this->assertSame('https://child.example.net/x', $handler->trustChildSiteHosts(admin_url(), 'https://child.example.net/x'));
            $this->assertSame(admin_url(), $handler->trustChildSiteHosts(admin_url(), self::OFF_SITE));
        } finally {
            delete_option('__fls_child_sites');
        }
    }

    public function test_the_passkey_reply_is_clamped()
    {
        $user = $this->makeUser('subscriber');
        add_filter('login_redirect', [$this, 'sendOffSite'], 1000);

        $method = new \ReflectionMethod(PasskeyLoginHandler::class, 'getRedirectUrl');

        $this->assertSame(admin_url(), $method->invoke(new PasskeyLoginHandler(), $user));
    }

    public function test_a_magic_link_does_not_store_an_off_site_destination()
    {
        $settings = get_option('__fls_auth_settings', []);
        $settings['magic_login'] = 'yes';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $user = $this->makeUser('subscriber');
        $_GET['redirect_to'] = self::OFF_SITE;

        $method = new \ReflectionMethod(MagicLoginHandler::class, 'getMagicLoginUrl');
        $method->invoke(new MagicLoginHandler(), $user, 5);

        $row = flsDb()->table('fls_login_hashes')->where('user_id', $user->ID)->orderBy('id', 'DESC')->first();

        $this->assertNotNull($row);
        $this->assertEmpty($row->redirect_intend);
    }

    // -------------------------------------------------------------------- helpers

    private function makeUser($role, $login = null)
    {
        $id = $this->factory->user->create([
            'role'       => $role,
            'user_login' => $login ?: 'redirect_' . wp_generate_password(6, false),
            'user_pass'  => 'correct horse battery'
        ]);

        return get_user_by('ID', $id);
    }

    private function setLoginRedirect($url)
    {
        update_option('__fls_auth_forms_settings', [
            'enabled'                => 'yes',
            'login_redirects'        => 'yes',
            'default_login_redirect' => $url
        ]);
        Helper::resetStatics();
    }

    private function loginReply($login)
    {
        $_REQUEST['_nonce'] = wp_create_nonce('fsecurity_login_nonce');
        $_REQUEST['_is_fls_form'] = 1;
        $_REQUEST['log'] = $_POST['log'] = $login;
        $_REQUEST['pwd'] = $_POST['pwd'] = 'correct horse battery';

        return $this->captureJson(function () {
            (new CustomAuthHandler())->handleLoginAjax();
        });
    }

    private function captureJson(callable $run)
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
            $run();
        } catch (\WPDieException $e) {
            // expected: wp_send_json() ends the request
        }
        $output = ob_get_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('wp_die_ajax_handler', $die);

        return (array)json_decode($output, true);
    }
}
