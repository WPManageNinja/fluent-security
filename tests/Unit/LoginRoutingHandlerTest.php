<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\LoginRoutingHandler;
use FluentAuth\App\Http\Controllers\SettingsController;
use FluentAuth\App\Services\TwoFa\TwoFaService;

class LoginRoutingHandlerTest extends BaseTestCase
{
    private $pageId;
    private $requestBackup;

    public function setUp(): void
    {
        parent::setUp();
        $this->requestBackup = [$_GET, $_REQUEST, $_SERVER, $GLOBALS['pagenow']];
        $_GET = $_REQUEST = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $GLOBALS['pagenow'] = 'wp-login.php';
        wp_set_current_user(0);
        $this->pageId = self::factory()->post->create([
            'post_type' => 'page', 'post_status' => 'publish', 'post_content' => '[fluent_auth]'
        ]);
        update_option('__fls_auth_forms_settings', [
            'enabled' => 'yes', 'redirect_wp_login' => 'yes', 'login_page_id' => $this->pageId,
            'legacy_key' => 'retained', 'default_logout_redirect' => home_url('/goodbye/')
        ]);
    }

    public function tearDown(): void
    {
        [$_GET, $_REQUEST, $_SERVER, $GLOBALS['pagenow']] = $this->requestBackup;
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_settings_save_the_selected_login_page_and_routing_policy()
    {
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes', 'legacy_key' => 'retained']);
        $result = $this->save(['enabled' => 'yes', 'login_page_id' => (string) $this->pageId, 'redirect_wp_login' => 'yes']);
        $this->assertNotWPError($result);
        $stored = get_option('__fls_auth_forms_settings');
        $this->assertSame($this->pageId, $stored['login_page_id'] ?? null);
        $this->assertSame('yes', $stored['redirect_wp_login'] ?? null);
        $this->assertSame('yes', $stored['enabled']);
        $this->assertSame('retained', $stored['legacy_key']);
    }

    public function test_enabled_routing_preserves_the_validated_destination()
    {
        $_GET['redirect_to'] = home_url('/members/');
        $this->assertSame(add_query_arg('redirect_to', home_url('/members/'), get_permalink($this->pageId)), (new LoginRoutingHandler())->getRedirectUrl());
        $_GET['redirect_to'] = 'https://untrusted.example/login';
        $this->assertSame(get_permalink($this->pageId), (new LoginRoutingHandler())->getRedirectUrl());
        $_GET['redirect_to'] = ['invalid'];
        $this->assertSame(get_permalink($this->pageId), (new LoginRoutingHandler())->getRedirectUrl());
    }

    /** @dataProvider technicalRequests */
    public function test_technical_requests_stay_on_core($method, $query)
    {
        $_SERVER['REQUEST_METHOD'] = $method;
        $_GET = $_REQUEST = $query;
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
    }

    public function technicalRequests()
    {
        return [
            ['POST', []], ['HEAD', []], ['PUT', []],
            ['GET', ['action' => 'logout']], ['GET', ['action' => 'lostpassword']],
            ['GET', ['action' => 'retrievepassword']], ['GET', ['action' => 'rp']],
            ['GET', ['action' => 'resetpass']], ['GET', ['action' => 'register']],
            ['GET', ['action' => 'fls_2fa_email']], ['GET', ['action' => 'fls_2fa_switch']],
            ['GET', ['action' => 'unknown_plugin_action']], ['GET', ['action' => ['login']]],
            ['GET', ['interim-login' => '1']], ['GET', ['customize-login' => '1']],
            ['GET', ['fs_auth' => 'google']], ['GET', ['fls_al' => 'synthetic']],
            ['GET', ['key' => 'synthetic']], ['GET', ['checkemail' => 'confirm']],
            ['GET', ['fls_2fa' => 'verify']], ['GET', ['loggedout' => 'true']]
        ];
    }

    public function test_guest_admin_entry_routes_but_signed_in_reauthentication_does_not()
    {
        $_GET = $_REQUEST = ['action' => 'login', 'reauth' => '1'];
        $this->assertSame(get_permalink($this->pageId), (new LoginRoutingHandler())->getRedirectUrl());
        wp_set_current_user(self::factory()->user->create(['role' => 'subscriber']));
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        wp_set_current_user(0);
        $GLOBALS['pagenow'] = 'index.php';
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
    }

    public function test_legacy_options_default_to_disabled_without_writing()
    {
        $legacy = ['enabled' => 'yes', 'default_login_redirect' => home_url('/account/')];
        update_option('__fls_auth_forms_settings', $legacy);
        $settings = Helper::getAuthFormsSettings();
        $this->assertSame('no', $settings['redirect_wp_login']);
        $this->assertSame(0, $settings['login_page_id']);
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        $this->assertSame($legacy, get_option('__fls_auth_forms_settings'));
    }

    /** @dataProvider unavailablePages */
    public function test_unavailable_or_incompatible_page_falls_back_to_core($changes)
    {
        wp_update_post(array_merge(['ID' => $this->pageId], $changes));
        if (isset($changes['post_content'])) {
            $this->preserveRawContent($changes['post_content']);
        }
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        $before = get_option('__fls_auth_forms_settings');
        $this->assertWPError($this->save(['redirect_wp_login' => 'yes']));
        $this->assertSame($before, get_option('__fls_auth_forms_settings'));
        $choices = SettingsController::getAuthFormSettings(new \WP_REST_Request());
        $this->assertNotContains($this->pageId, array_column($choices['login_pages'], 'id'));
    }

    public function unavailablePages()
    {
        return [
            [['post_status' => 'draft']], [['post_status' => 'private']], [['post_status' => 'trash']],
            [['post_password' => 'local-only']], [['post_content' => '[fluent_auth_signup]']],
            [['post_content' => 'No form']], [['post_content' => '[[fluent_auth]]']], [['post_type' => 'post']],
            [['post_content' => '<!-- [fluent_auth] -->']],
            [['post_content' => '<![CDATA[ [fluent_auth_login] ]]>']],
            [['post_content' => '[fluent_<!-- interrupted -->auth]']]
        ];
    }

    /** @dataProvider mixedCommentContent */
    public function test_only_active_shortcode_occurrences_make_a_page_usable($content)
    {
        $this->preserveRawContent($content);
        $this->assertSame(get_permalink($this->pageId), (new LoginRoutingHandler())->getRedirectUrl());
        $this->assertNotWPError($this->save(['redirect_wp_login' => 'yes']));
        $choices = SettingsController::getAuthFormSettings(new \WP_REST_Request());
        $this->assertContains($this->pageId, array_column($choices['login_pages'], 'id'));
    }

    public function mixedCommentContent()
    {
        return [
            ['<!-- [fluent_auth] --> [fluent_auth_login]'],
            ['<![CDATA[ [fluent_auth_login] ]]> [fluent_auth]'],
            ['<!-- wp:shortcode -->[fluent_auth]<!-- /wp:shortcode -->']
        ];
    }

    public function test_cleared_target_can_be_saved_with_routing_off()
    {
        $this->assertNotWPError($this->save(['login_page_id' => 0, 'redirect_wp_login' => 'no']));
        $this->assertSame(0, Helper::getAuthFormsSettings()['login_page_id']);
        $this->assertSame('no', Helper::getAuthFormsSettings()['redirect_wp_login']);
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
    }

    public function test_forms_off_and_missing_page_disable_routing()
    {
        $this->assertNotWPError($this->save(['enabled' => 'no']));
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        $this->assertSame('no', Helper::getAuthFormsSettings()['redirect_wp_login']);
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes', 'redirect_wp_login' => 'yes', 'login_page_id' => PHP_INT_MAX]);
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
    }

    public function test_other_forms_saves_preserve_routing_and_legacy_keys()
    {
        $this->assertNotWPError($this->save(['enabled' => 'yes']));
        $request = new \WP_REST_Request();
        $request->set_param('redirect_settings', ['login_redirects' => 'no']);
        $this->assertNotWPError(SettingsController::saveAuthFormSettings($request));
        $settings = get_option('__fls_auth_forms_settings');
        $this->assertSame($this->pageId, $settings['login_page_id']);
        $this->assertSame('yes', $settings['redirect_wp_login']);
        $this->assertSame('retained', $settings['legacy_key']);
    }

    /** @dataProvider malformedSettings */
    public function test_invalid_routing_payloads_do_not_write($changes)
    {
        $before = get_option('__fls_auth_forms_settings');
        $this->assertWPError($this->save($changes));
        $this->assertSame($before, get_option('__fls_auth_forms_settings'));
    }

    public function malformedSettings()
    {
        return [[['login_page_id' => []]], [['login_page_id' => '-1']], [['login_page_id' => '1.5']],
            [['redirect_wp_login' => '404']], [['redirect_wp_login' => []]], [['login_page_id' => '0']]];
    }

    public function test_page_choices_are_valid_and_technical_urls_remain_core()
    {
        self::factory()->post->create(['post_type' => 'page', 'post_status' => 'publish', 'post_content' => 'No form']);
        $result = SettingsController::getAuthFormSettings(new \WP_REST_Request());
        $this->assertContains($this->pageId, array_column($result['login_pages'], 'id'));
        $this->assertCount(1, $result['login_pages']);
        $this->assertSame('/wp-login.php', wp_parse_url(TwoFaService::getChallengeUrl('synthetic'), PHP_URL_PATH));
        $this->assertSame('/wp-login.php', wp_parse_url(TwoFaService::getSwitchUrl('synthetic'), PHP_URL_PATH));
    }

    public function test_login_only_shortcode_and_subdirectory_site_urls()
    {
        update_option('home', 'https://example.org/members');
        update_option('siteurl', 'https://example.org/wordpress');
        wp_update_post(['ID' => $this->pageId, 'post_content' => '[fluent_auth_login]']);
        $this->assertSame(get_permalink($this->pageId), (new LoginRoutingHandler())->getRedirectUrl());
        add_filter('page_link', [$this, 'coreLoginPermalink']);
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        remove_filter('page_link', [$this, 'coreLoginPermalink']);
        add_filter('page_link', [$this, 'offsitePermalink']);
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        remove_filter('page_link', [$this, 'offsitePermalink']);
    }

    public function coreLoginPermalink()
    {
        return site_url('wp-login.php');
    }

    public function offsitePermalink()
    {
        return 'https://untrusted.example/login';
    }

    public function test_disabling_forms_through_the_existing_filter_preserves_core()
    {
        add_filter('fluent_auth/auth_forms_enabled', '__return_false');
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        remove_filter('fluent_auth/auth_forms_enabled', '__return_false');
    }

    public function test_repeated_routing_does_not_write_settings_or_register_a_global_url_filter()
    {
        $before = get_option('__fls_auth_forms_settings');
        $writes = 0;
        $observe = function () use (&$writes) { $writes++; };
        add_action('updated_option', $observe);
        for ($i = 0; $i < 3; $i++) {
            $this->assertSame(get_permalink($this->pageId), (new LoginRoutingHandler())->getRedirectUrl());
        }
        remove_action('updated_option', $observe);
        $this->assertSame(0, $writes);
        $this->assertSame($before, get_option('__fls_auth_forms_settings'));
        $this->assertSame(site_url('wp-login.php', 'login'), wp_login_url());
    }

    private function save($settings)
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', $settings);
        return SettingsController::saveAuthFormSettings($request);
    }

    private function preserveRawContent($content)
    {
        // Preserve imported/unfiltered saved content instead of letting fixture KSES remove CDATA.
        global $wpdb;
        $wpdb->update($wpdb->posts, ['post_content' => $content], ['ID' => $this->pageId]);
        clean_post_cache($this->pageId);
    }
}
