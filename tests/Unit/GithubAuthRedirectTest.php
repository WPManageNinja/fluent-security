<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\GithubAuthService;

/**
 * GitHub matches redirect URIs exactly, so the callback URL in the authorize link must
 * reach GitHub whole: the same value the settings screen tells the admin to register,
 * the same value the token exchange sends afterwards, and, so that sites where GitHub
 * sign-in works keep working, the same value GitHub received before this was fixed.
 */
class GithubAuthRedirectTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        update_option('__fls_social_auth_settings', [
            // Anything but 'wp_config', or the keys get read from constants instead.
            'github_key_method'    => 'db',
            'github_client_id'     => 'Ov23liTestClient',
            'github_client_secret' => 'secret',
            'enable_github'        => 'yes',
        ]);
        Helper::resetStatics();
    }

    private function queryOf($url)
    {
        parse_str((string)wp_parse_url($url, PHP_URL_QUERY), $query);

        return $query;
    }

    public function test_authorize_link()
    {
        $this->assertSame(
            'https://github.com/login/oauth/authorize?client_id=Ov23liTestClient'
            . '&redirect_uri=' . rawurlencode(wp_login_url() . '?fs_auth=github')
            . '&scope=user&state=st4te',
            GithubAuthService::getAuthRedirect('st4te')
        );
    }

    public function test_github_reads_the_url_the_settings_screen_shows()
    {
        $query = $this->queryOf(GithubAuthService::getAuthRedirect('st4te'));

        $this->assertSame(wp_login_url() . '?fs_auth=github', GithubAuthService::getAppRedirect());
        $this->assertSame(GithubAuthService::getAppRedirect(), $query['redirect_uri']);
        $this->assertSame('st4te', $query['state']);
    }

    public function test_authorize_and_token_exchange_send_the_same_redirect_uri()
    {
        $query = $this->queryOf(GithubAuthService::getAuthRedirect('st4te'));

        $this->assertSame(GithubAuthService::getAuthConfirmParams('code')['redirect_uri'], $query['redirect_uri']);
    }

    /**
     * The link as 3.1.1 built it: the callback ended in &fs_type=confirm and went out
     * unencoded. Whatever a site registered with GitHub, it matched what GitHub read
     * from that link; the new link must read the same.
     */
    public function test_github_receives_the_same_redirect_uri_as_before_the_fix()
    {
        $before = $this->queryOf(add_query_arg([
            'client_id'    => 'Ov23liTestClient',
            'redirect_uri' => add_query_arg(['fs_auth' => 'github', 'fs_type' => 'confirm'], wp_login_url()),
            'scope'        => 'user',
            'state'        => 'st4te'
        ], 'https://github.com/login/oauth/authorize'));

        $after = $this->queryOf(GithubAuthService::getAuthRedirect('st4te'));

        $this->assertSame(wp_login_url() . '?fs_auth=github', $before['redirect_uri']);
        $this->assertSame($before['redirect_uri'], $after['redirect_uri']);
        $this->assertArrayNotHasKey('fs_type', $after);
    }
}
