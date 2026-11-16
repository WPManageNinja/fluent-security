<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Http\Controllers\SettingsController;

class LoginPageRoutingTest extends BaseTestCase
{
    private $pageId;

    private $backup;

    public function setUp(): void
    {
        parent::setUp();
        $this->backup = [$_GET, $_COOKIE, $_SERVER];
        $_GET = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        wp_set_current_user(0);

        $this->pageId = self::factory()->post->create([
            'post_type' => 'page', 'post_status' => 'publish', 'post_content' => '[fluent_auth]'
        ]);

        update_option('__fls_auth_forms_settings', [
            'enabled' => 'yes', 'login_page_id' => $this->pageId, 'redirect_wp_login' => 'yes'
        ]);
    }

    public function tearDown(): void
    {
        [$_GET, $_COOKIE, $_SERVER] = $this->backup;
        delete_option('__fls_auth_forms_settings');
        wp_set_current_user(0);
        parent::tearDown();
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

    public function testAGuestVisitGoesToTheLoginPageWithASafeDestination()
    {
        $this->assertSame(get_permalink($this->pageId), $this->route());

        $_GET = ['redirect_to' => admin_url(), 'reauth' => '1'];
        $this->assertSame(add_query_arg('redirect_to', rawurlencode(admin_url()), get_permalink($this->pageId)), $this->route());

        $_GET = ['redirect_to' => 'https://evil.example/'];
        $this->assertSame(get_permalink($this->pageId), $this->route());
    }

    public function stayOnWordPress()
    {
        return [
            'password POST'      => [function () { $_SERVER['REQUEST_METHOD'] = 'POST'; }],
            'an action'          => [function () { $_GET = ['action' => 'lostpassword']; }],
            'another query key'  => [function () { $_GET = ['fls_2fa' => 'x']; }],
            'signed in'          => [function () { wp_set_current_user(1); }],
            'switch off'         => [function ($pageId) { update_option('__fls_auth_forms_settings', ['enabled' => 'yes', 'login_page_id' => $pageId, 'redirect_wp_login' => 'no']); }],
            'forms off'          => [function ($pageId) { update_option('__fls_auth_forms_settings', ['enabled' => 'no', 'login_page_id' => $pageId, 'redirect_wp_login' => 'yes']); }],
            'page not published' => [function ($pageId) { wp_update_post(['ID' => $pageId, 'post_status' => 'draft']); }],
            'sent back within a minute' => [function () { $_COOKIE['fls_login_routed'] = '1'; }],
        ];
    }

    /** @dataProvider stayOnWordPress */
    public function testTheseRequestsStayOnWordPress($change)
    {
        $change($this->pageId);

        $this->assertNull($this->route());
    }

    public function testClearingThePageTurnsTheSwitchOff()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', ['enabled' => 'yes', 'login_page_id' => '', 'redirect_wp_login' => 'yes']);
        $saved = SettingsController::saveAuthFormSettings($request)['settings'];

        $this->assertSame(0, $saved['login_page_id']);
        $this->assertSame('no', $saved['redirect_wp_login']);

        $request->set_param('settings', ['enabled' => 'yes', 'login_page_id' => (string)$this->pageId, 'redirect_wp_login' => 'yes']);
        $saved = SettingsController::saveAuthFormSettings($request)['settings'];

        $this->assertSame($this->pageId, $saved['login_page_id']);
        $this->assertSame('yes', $saved['redirect_wp_login']);
    }
}
