<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\MagicLoginHandler;
use FluentAuth\App\Hooks\Handlers\PasskeyLoginHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
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
     * The site owner typed this address into the login redirect settings themselves, so
     * its host is one they trust - another domain, a shop on a subdomain.
     */
    public function test_a_login_redirect_the_owner_configured_may_leave_the_site()
    {
        $this->setLoginRedirect('https://shop.example.org/welcome/');
        $this->makeUser('subscriber', 'redirect_probe');

        $reply = $this->loginReply('redirect_probe');

        $this->assertSame('https://shop.example.org/welcome/', $reply['redirect']);
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
