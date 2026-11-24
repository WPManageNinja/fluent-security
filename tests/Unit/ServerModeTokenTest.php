<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\ServerModeHandler;
use FluentAuth\App\Http\Controllers\SettingsController;

/**
 * The sign-in token a server-mode site hands to a child site.
 */
class ServerModeTokenTest extends BaseTestCase
{
    private $user;

    public function setUp(): void
    {
        parent::setUp();

        update_option('__fls_child_sites', [
            'aaaa' => [
                'site_id'      => 'aaaa',
                'site_url'     => 'https://child-a.example',
                'callback_url' => 'https://child-a.example/wp-login.php?fluent_auth_c=1',
                'secret_key'   => 'secret-a-0123456789abcdef0123456',
                'title'        => 'A',
                'status'       => 'yes'
            ],
            'bbbb' => [
                'site_id'      => 'bbbb',
                'site_url'     => 'https://child-b.example',
                'callback_url' => 'https://child-b.example/wp-login.php?fluent_auth_c=1',
                'secret_key'   => 'secret-b-0123456789abcdef0123456',
                'title'        => 'B',
                'status'       => 'yes'
            ]
        ]);

        $this->user = $this->factory->user->create_and_get(['role' => 'administrator']);
    }

    public function tearDown(): void
    {
        unset($_COOKIE['__fls_auth_client_id']);
        delete_option('__fls_child_sites');
        parent::tearDown();
    }

    private function tokenMintedFor($siteId)
    {
        $_COOKIE['__fls_auth_client_id'] = $siteId;

        // @: setcookie() warns once the test runner has printed anything.
        $url = @(new ServerModeHandler())->maybeRemoteLoginRedirect(admin_url(), '', $this->user);

        parse_str((string)wp_parse_url($url, PHP_URL_QUERY), $query);

        $this->assertNotEmpty($query['fluent_auth_token'], 'a token should have been minted');

        return $query['fluent_auth_token'];
    }

    private function redeem($token, $siteId)
    {
        $sites = get_option('__fls_child_sites');

        $request = new \WP_REST_Request('POST', '/fluent-auth/child-sites/validate-token');
        $request->set_param('user_token', $token);
        $request->set_param('server_token', $sites[$siteId]['secret_key']);
        $request->set_param('site_id', $siteId);

        return SettingsController::validateChildSiteToken($request);
    }

    public function test_another_child_cannot_redeem_the_token()
    {
        $token = $this->tokenMintedFor('aaaa');

        $this->assertWpErrorWithCode($this->redeem($token, 'bbbb'), 'invalid_request');

        // Spent, so the attempt also costs the stolen token its value.
        $this->assertWpErrorWithCode($this->redeem($token, 'aaaa'), 'invalid_request');
    }

    public function test_the_child_it_was_sent_to_redeems_it_once()
    {
        $token = $this->tokenMintedFor('aaaa');

        $reply = $this->redeem($token, 'aaaa');

        $this->assertIsArray($reply);
        $this->assertSame($this->user->user_login, $reply['user_data']['user_login']);

        $this->assertWpErrorWithCode($this->redeem($token, 'aaaa'), 'invalid_request');
    }

    public function test_a_failed_login_mints_nothing()
    {
        $_COOKIE['__fls_auth_client_id'] = 'aaaa';

        $result = (new ServerModeHandler())->maybeRemoteLoginRedirect(
            admin_url(),
            '',
            new \WP_Error('incorrect_password', 'no')
        );

        $this->assertSame(admin_url(), $result);
        $this->assertSame('', (string)get_user_meta($this->user->ID, '__flsc_temp_token', true));
    }
}
