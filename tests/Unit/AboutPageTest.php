<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\AboutController;
use FluentAuth\App\Services\AboutPage;

class AboutPageTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        delete_transient(AboutPage::CONTRIBUTORS_CACHE);
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));
    }

    public function test_it_lists_the_hand_picked_plugins_with_their_state()
    {
        $plugins = AboutPage::plugins();

        $this->assertSame(
            ['fluent-smtp', 'fluent-crm', 'fluent-cart', 'fluentform', 'fluent-community', 'fluent-booking', 'fluent-support'],
            array_column($plugins, 'slug')
        );

        foreach ($plugins as $plugin) {
            $this->assertContains($plugin['state'], ['active', 'installed', 'missing']);
            $this->assertNotSame('', $plugin['pitch']);
            $this->assertStringContainsString('dist/images/plugins/' . $plugin['slug'] . '.', $plugin['icon']);
        }
    }

    public function test_only_plugins_on_the_list_can_be_installed()
    {
        $result = AboutPage::installAndActivate('hello-dolly');

        $this->assertWPError($result);
        $this->assertSame('unknown_plugin', $result->get_error_code());
    }

    public function test_someone_who_cannot_activate_plugins_is_refused()
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'editor']));

        $result = AboutPage::installAndActivate('fluent-smtp');

        $this->assertWPError($result);
        $this->assertSame('forbidden', $result->get_error_code());
    }

    /** A host can block one plugin through activate_plugin; this screen must respect that. */
    public function test_a_plugin_the_site_blocks_from_activation_is_refused()
    {
        $block = function ($caps, $cap, $userId, $args) {
            if ($cap === 'activate_plugin' && ($args[0] ?? '') === 'fluent-smtp/fluent-smtp.php') {
                return ['do_not_allow'];
            }
            return $caps;
        };
        add_filter('map_meta_cap', $block, 10, 4);

        try {
            $result = AboutPage::installAndActivate('fluent-smtp');
        } finally {
            remove_filter('map_meta_cap', $block, 10);
        }

        $this->assertWPError($result);
        $this->assertSame('forbidden', $result->get_error_code());
    }

    public function test_the_install_endpoint_returns_the_error_rather_than_installing()
    {
        $request = new \WP_REST_Request('POST', '/fluent-auth/about/install-plugin');
        $request->set_param('slug', '../../evil');

        $this->assertWPError(AboutController::installPlugin($request));
    }

    public function test_contributors_come_from_github_without_the_site_address_and_are_cached()
    {
        $calls = [];
        $stub = function ($pre, $args, $url) use (&$calls) {
            $calls[] = ['url' => $url, 'ua' => $args['user-agent'] ?? ''];

            return [
                'headers'  => [],
                'response' => ['code' => 200, 'message' => 'OK'],
                'cookies'  => [],
                'body'     => wp_json_encode([
                    ['login' => 'techjewel', 'type' => 'User', 'avatar_url' => 'https://avatars.githubusercontent.com/u/1?v=4', 'html_url' => 'https://github.com/techjewel'],
                    ['login' => 'dependabot[bot]', 'type' => 'Bot', 'avatar_url' => 'https://avatars.githubusercontent.com/u/2', 'html_url' => 'https://github.com/apps/dependabot'],
                ])
            ];
        };
        add_filter('pre_http_request', $stub, 10, 3);

        try {
            $first = AboutPage::contributors();
            $second = AboutPage::contributors();
        } finally {
            remove_filter('pre_http_request', $stub, 10);
        }

        $this->assertSame(['techjewel'], array_column($first, 'login'), 'Bots are left out');
        $this->assertStringContainsString('s=96', $first[0]['avatar']);
        $this->assertSame($first, $second);
        $this->assertCount(1, $calls, 'The second visit is served from the cache');
        $this->assertSame('FluentAuth', $calls[0]['ua']);
        $this->assertStringNotContainsString(home_url(), $calls[0]['ua']);
    }

    public function test_an_unreachable_github_leaves_an_empty_list_and_retries_later()
    {
        $stub = function () {
            return new \WP_Error('http_request_failed', 'timeout');
        };
        add_filter('pre_http_request', $stub);

        try {
            $people = AboutPage::contributors();
        } finally {
            remove_filter('pre_http_request', $stub);
        }

        $this->assertSame([], $people);
        $this->assertSame([], get_transient(AboutPage::CONTRIBUTORS_CACHE));
    }
}
