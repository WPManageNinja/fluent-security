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

        $_GET = ['redirect_to' => admin_url(), 'reauth' => '1'];
        $this->assertSame(add_query_arg('redirect_to', rawurlencode(admin_url()), $this->loginPage), $this->route());

        $_GET = ['redirect_to' => 'https://evil.example/'];
        $this->assertSame($this->loginPage, $this->route());
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
            'sent back within a minute' => [function () { $_COOKIE['fls_login_routed'] = '1'; }],
        ];
    }

    /** @dataProvider stayOnWordPress */
    public function testTheseRequestsStayOnWordPress($change)
    {
        $change();

        $this->assertNull($this->route());
    }
}
