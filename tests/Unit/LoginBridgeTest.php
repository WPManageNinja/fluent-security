<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Services\LoginBridge;

/**
 * The seam another plugin uses to run its own auth screen on FluentAuth.
 *
 * The case behind all of this: FluentCommunity's portal read the shortcode setting as
 * "may I use FluentAuth here", and on a site that had the front end forms switched off
 * it rendered a login form of its own while FluentAuth carried on injecting magic login
 * into it and refusing the login without a second factor it had nowhere to show.
 */
class LoginBridgeTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        update_option('__fls_auth_forms_settings', ['enabled' => 'no']);
        unset($_REQUEST['is_host_screen'], $_REQUEST['_fls_host'], $_REQUEST['_fls_host_sig'], $_REQUEST['action']);
    }

    public function tearDown(): void
    {
        unset($_REQUEST['is_host_screen'], $_REQUEST['_fls_host'], $_REQUEST['_fls_host_sig'], $_REQUEST['action']);
        parent::tearDown();
    }

    private function handler()
    {
        return new CustomAuthHandler();
    }

    public function test_forms_stay_off_when_nothing_has_adopted_them()
    {
        $this->assertFalse($this->handler()->isEnabled());
        $this->assertFalse(LoginBridge::claimed());
    }

    public function test_the_site_setting_still_turns_the_forms_on_by_itself()
    {
        update_option('__fls_auth_forms_settings', ['enabled' => 'yes']);

        $this->assertTrue($this->handler()->isEnabled());
    }

    /**
     * Registering says "I exist", not "this request is mine". A host that owns one
     * screen must not switch the forms on for the whole site.
     */
    public function test_registering_alone_does_not_claim_a_request()
    {
        LoginBridge::register('test-host', 'is_host_screen');

        $this->assertFalse(LoginBridge::claimed());
        $this->assertFalse($this->handler()->isEnabled());
    }

    public function test_a_registered_host_claims_the_request_carrying_its_field()
    {
        LoginBridge::register('test-host', 'is_host_screen');
        $_REQUEST['is_host_screen'] = 'yes';

        $this->assertTrue(LoginBridge::claimed());
        $this->assertTrue($this->handler()->isEnabled());
    }

    public function test_a_callable_claim_decides_for_itself()
    {
        LoginBridge::register('test-host', function () {
            return true;
        });

        $this->assertTrue($this->handler()->isEnabled());
    }

    public function test_adopting_turns_the_forms_on_for_the_screen_being_rendered()
    {
        LoginBridge::register('test-host', 'is_host_screen');

        // No field on this request: the host is rendering, not posting back.
        $this->assertFalse($this->handler()->isEnabled());

        LoginBridge::adopt(['host' => 'test-host']);

        $this->assertTrue($this->handler()->isEnabled());
    }

    /**
     * The marker is what carries the adoption into the post the form makes. Without it
     * only a form the host put its own field on would be recognised, which is how a
     * host's password reset - a form it never touches - would be refused.
     */
    public function test_adopting_marks_the_forms_it_renders()
    {
        LoginBridge::adopt(['host' => 'test-host']);

        $markup = LoginBridge::markerFields();

        $this->assertStringContainsString('name="_fls_host" value="test-host"', $markup);
        $this->assertMatchesRegularExpression('/name="_fls_host_sig" value="[a-f0-9]+"/', $markup);
    }

    public function test_an_unadopted_request_renders_no_marker()
    {
        $this->assertSame('', LoginBridge::markerFields());
    }

    public function test_a_signed_marker_claims_the_request_it_comes_back_on()
    {
        LoginBridge::register('test-host', 'is_host_screen');

        $_REQUEST['_fls_host'] = 'test-host';
        $_REQUEST['_fls_host_sig'] = wp_create_nonce(LoginBridge::MARKER_ACTION . 'test-host');

        $this->assertTrue(LoginBridge::claimed());
        $this->assertTrue($this->handler()->isEnabled());
    }

    /**
     * The guard that keeps this from being a way around the setting. A visitor can put
     * any field they like on a post; what they cannot do is run register().
     */
    public function test_a_marker_for_an_unregistered_host_claims_nothing()
    {
        $_REQUEST['_fls_host'] = 'test-host';
        $_REQUEST['_fls_host_sig'] = wp_create_nonce(LoginBridge::MARKER_ACTION . 'test-host');

        $this->assertFalse(LoginBridge::claimed());
        $this->assertFalse($this->handler()->isEnabled());
    }

    public function test_an_unsigned_marker_claims_nothing()
    {
        LoginBridge::register('test-host', 'is_host_screen');

        $_REQUEST['_fls_host'] = 'test-host';
        $_REQUEST['_fls_host_sig'] = 'not-a-nonce';

        $this->assertFalse(LoginBridge::claimed());
    }

    public function test_a_marker_signed_for_another_host_claims_nothing()
    {
        LoginBridge::register('test-host', 'is_host_screen');

        $_REQUEST['_fls_host'] = 'test-host';
        $_REQUEST['_fls_host_sig'] = wp_create_nonce(LoginBridge::MARKER_ACTION . 'other-host');

        $this->assertFalse(LoginBridge::claimed());
    }

    public function test_the_site_can_refuse_an_adoption_outright()
    {
        add_filter('fluent_auth/auth_forms_enabled', '__return_false', 99);

        LoginBridge::adopt(['host' => 'test-host']);

        $this->assertFalse($this->handler()->isEnabled());

        remove_filter('fluent_auth/auth_forms_enabled', '__return_false', 99);
    }

    /**
     * The lighter tier: a host that keeps its own login endpoint and only wants the
     * second factor to come back as markup instead of a WP_Error.
     */
    public function test_a_declared_ajax_action_may_render_the_second_factor_inline()
    {
        LoginBridge::register('test-host', 'is_host_screen', ['host_login']);

        $_REQUEST['action'] = 'host_login';
        $this->assertTrue(apply_filters('fluent_auth/can_render_2fa_inline', false));

        $_REQUEST['action'] = 'something_else';
        $this->assertFalse(apply_filters('fluent_auth/can_render_2fa_inline', false));
    }

    public function test_hidden_fields_are_printed_inside_the_form()
    {
        LoginBridge::adopt([
            'host'          => 'test-host',
            'hidden_fields' => ['host_token' => 'abc123']
        ]);

        $html = apply_filters('login_form_top', '', []);

        $this->assertStringContainsString('name="host_token" value="abc123"', $html);
    }

    public function test_a_redirect_is_carried_into_the_form_args()
    {
        LoginBridge::adopt([
            'host'        => 'test-host',
            'redirect_to' => 'https://example.test/portal'
        ]);

        $args = apply_filters('fluent_auth/login_form_args', []);

        $this->assertSame('https://example.test/portal', $args['redirect']);
        $this->assertSame('https://example.test/portal', $args['force_redirect_to']);
        $this->assertSame('https://example.test/portal', apply_filters('fluent_auth/social_redirect_to', ''));
    }
}
