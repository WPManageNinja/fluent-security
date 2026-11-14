<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\LoginRoutingHandler;
use FluentAuth\App\Http\Controllers\SettingsController;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class LoginRoutingConstantTest extends BaseTestCase
{
    public function test_configuration_override_restores_core_without_changing_saved_settings()
    {
        $GLOBALS['pagenow'] = 'wp-login.php';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET = $_REQUEST = [];
        wp_set_current_user(0);
        $pageId = self::factory()->post->create([
            'post_type' => 'page', 'post_status' => 'publish', 'post_content' => '[fluent_auth]'
        ]);
        $settings = ['enabled' => 'yes', 'redirect_wp_login' => 'yes', 'login_page_id' => $pageId];
        update_option('__fls_auth_forms_settings', $settings);
        $this->assertSame(get_permalink($pageId), (new LoginRoutingHandler())->getRedirectUrl());
        define('FLUENT_AUTH_DISABLE_LOGIN_ROUTING', true);
        $this->assertSame('', (new LoginRoutingHandler())->getRedirectUrl());
        $this->assertSame($settings, get_option('__fls_auth_forms_settings'));
        $this->assertTrue(SettingsController::getAuthFormSettings(new \WP_REST_Request())['login_routing_disabled']);
    }
}
