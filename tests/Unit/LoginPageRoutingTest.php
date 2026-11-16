<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;

class LoginPageRoutingTest extends BaseTestCase
{
    private $backup;

    private $loginPage;

    public function setUp(): void
    {
        parent::setUp();
        $this->backup = [$_GET, $_COOKIE, $_SERVER];
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        wp_set_current_user(0);

        $this->loginPage = home_url('/sign-in/');
        add_filter('fluent_auth/login_page_url', [$this, 'loginPageUrl']);
    }

    public function tearDown(): void
    {
        remove_filter('fluent_auth/login_page_url', [$this, 'loginPageUrl']);
        [$_GET, $_COOKIE, $_SERVER] = $this->backup;
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function loginPageUrl()
    {
        return $this->loginPage;
    }

    /**
     * @return string|null where the browser was sent, or null when WordPress keeps the request
     */
    private function route()
    {
        $stop = function ($location) {
            throw new \RuntimeException($location);
        };
        add_filter('wp_redirect', $stop);

        try {
            (new CustomAuthHandler())->maybeRouteToLoginPage();
            return null;
        } catch (\RuntimeException $e) {
            return $e->getMessage();
        } finally {
            remove_filter('wp_redirect', $stop);
        }
    }

    public function testAGuestVisitGoesToTheFilteredPageWithASafeDestination()
    {
        $this->assertSame($this->loginPage, $this->route());

        $_GET = ['redirect_to' => admin_url('post.php?post=5&action=edit'), 'reauth' => '1'];
        $location = $this->route();
        $this->assertSame($this->loginPage, strtok($location, '?'));
        parse_str((string)wp_parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame(['redirect_to' => admin_url('post.php?post=5&action=edit')], $query);

        $_GET = ['loggedout' => 'true', 'wp_lang' => 'en_US'];
        $this->assertSame($this->loginPage, $this->route(), 'logouts go to the page too');

        $_GET = ['redirect_to' => 'https://evil.example/'];
        $this->assertSame($this->loginPage, $this->route());
    }

    public function testItRunsOnLoginInitBeforeTheLoginScreenCustomizer()
    {
        global $wp_filter;

        $found = false;
        foreach ($wp_filter['login_init']->callbacks[5] ?? [] as $callback) {
            $found = $found || (is_array($callback['function']) && $callback['function'][0] instanceof CustomAuthHandler
                && $callback['function'][1] === 'maybeRouteToLoginPage');
        }

        $this->assertTrue($found, 'the plugin registers it on login_init at priority 5');
    }

    public function testNothingChangesWithoutTheFilterOrWithAnOffSiteUrl()
    {
        $this->loginPage = '';
        $this->assertNull($this->route());

        $this->loginPage = 'https://evil.example/login/';
        $this->assertNull($this->route());
    }

    public function stayOnWordPress()
    {
        return [
            'password POST'             => [function () { $_SERVER['REQUEST_METHOD'] = 'POST'; }],
            'an action'                 => [function () { $_GET = ['action' => 'lostpassword']; }],
            'another query key'         => [function () { $_GET = ['fls_2fa' => 'x']; }],
            'signed in'                 => [function () { wp_set_current_user(1); }],
            'sent back within seconds'  => [function () { $_COOKIE['fls_login_routed'] = '1'; }],
        ];
    }

    /** @dataProvider stayOnWordPress */
    public function testTheseRequestsStayOnWordPress($change)
    {
        $change();

        $this->assertNull($this->route());
    }
}
