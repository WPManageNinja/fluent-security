<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\MagicLoginHandler;
use FluentAuth\App\Hooks\Handlers\PasskeyLoginHandler;
use FluentAuth\App\Services\LoginAssets;

/**
 * The one script the login screens load, and the one object it reads.
 *
 * Two bundles became one so that the passkey button and the magic link - which both
 * move themselves into the login form on DOMContentLoaded - stop racing. The things
 * worth pinning are that every entry point now asks the same loader, that the loader
 * hands the browser everything both features need, and that no login form carries
 * behaviour of its own any more.
 */
class LoginAssetsTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        LoginAssets::reset();
        wp_dequeue_script('fluent_auth_login_helper');
        wp_deregister_script('fluent_auth_login_helper');
        wp_dequeue_style('fluent_auth_login_helper');
        wp_deregister_style('fluent_auth_login_helper');
    }

    public function tearDown(): void
    {
        LoginAssets::reset();
        unset($_REQUEST['action'], $_REQUEST['redirect_to']);
        parent::tearDown();
    }

    // ------------------------------------------------------------------ the loader

    public function test_it_enqueues_the_one_helper_script()
    {
        LoginAssets::enqueue();

        $this->assertTrue(wp_script_is('fluent_auth_login_helper', 'enqueued'));
    }

    /**
     * The rules used to be injected by style-loader from inside the bundle, which put them
     * in <head> before wp-login.php had printed login.css. Core's `.login *` reset ties on
     * specificity with any single-class rule, so it won on order and flattened the magic
     * form's padding and gaps. A stylesheet in the queue is read after core's.
     */
    public function test_it_enqueues_the_login_stylesheet()
    {
        LoginAssets::enqueue();

        $this->assertTrue(wp_style_is('fluent_auth_login_helper', 'enqueued'));
    }

    /**
     * Every renderer on a login screen asks for the assets, because any of them might be
     * the first one on the page. Localising twice would print the config object twice.
     */
    public function test_asking_twice_enqueues_once()
    {
        LoginAssets::enqueue();
        LoginAssets::enqueue();

        $data = wp_scripts()->get_data('fluent_auth_login_helper', 'data');

        $this->assertSame(
            1,
            substr_count((string)$data, 'var fluentAuthPublic'),
            'the config object was printed more than once'
        );
    }

    public function test_the_config_carries_what_the_shortcode_forms_post_with()
    {
        LoginAssets::enqueue();

        $config = $this->localizedConfig();

        $this->assertNotEmpty($config['ajax_url']);
        $this->assertNotEmpty($config['fls_login_nonce']);
        $this->assertNotEmpty($config['i18n']['Username_or_Email']);
        $this->assertNotEmpty($config['i18n']['Password']);
    }

    /**
     * The script tests for this key before it touches the magic form at all, so its
     * absence has to mean "switched off" rather than "switched on with empty settings".
     */
    public function test_the_magic_settings_are_absent_when_magic_login_is_off()
    {
        $this->setSettings(['magic_login' => 'no']);

        LoginAssets::enqueue();

        $this->assertArrayNotHasKey('magic', $this->localizedConfig());
    }

    public function test_the_magic_settings_travel_with_the_script_when_it_is_on()
    {
        $this->setSettings(['magic_login' => 'yes', 'magic_link_primary' => 'yes']);

        LoginAssets::enqueue();

        $magic = $this->localizedConfig()['magic'];

        $this->assertNotEmpty($magic['success_icon']);
        $this->assertNotEmpty($magic['empty_text']);
        $this->assertNotEmpty($magic['wait_text']);
        $this->assertTrue($magic['is_primary']);
    }

    // ---------------------------------------------------------- everyone asks for it

    public function test_the_shortcode_forms_ask_for_it()
    {
        (new CustomAuthHandler())->loadAssets();

        $this->assertTrue(wp_script_is('fluent_auth_login_helper', 'enqueued'));
    }

    public function test_the_magic_login_form_asks_for_it()
    {
        $this->setSettings(['magic_login' => 'yes']);

        (new MagicLoginHandler())->pushAssets();

        $this->assertTrue(wp_script_is('fluent_auth_login_helper', 'enqueued'));
    }

    /**
     * The button is inert without the script, and it renders on wp-login.php - a page
     * that loaded neither bundle before this change.
     */
    public function test_the_passkey_login_button_asks_for_it()
    {
        $this->enablePasskeyLogin();

        $html = $this->renderPasskeyButton();

        $this->assertStringContainsString('id="fls_passkey_login_button"', $html);
        $this->assertTrue(wp_script_is('fluent_auth_login_helper', 'enqueued'));
    }

    public function test_the_passkey_login_button_carries_data_and_no_behaviour()
    {
        $this->enablePasskeyLogin();

        $html = $this->renderPasskeyButton();

        $this->assertDoesNotMatchRegularExpression(
            '#<script(?![^>]*type="application/json")[^>]*>\s*\S#',
            $html,
            'the passkey button still ships an inline script'
        );

        $pattern = '#<script type="application/json" id="fls_passkey_login_config">(.*?)</script>#s';
        $this->assertMatchesRegularExpression($pattern, $html);

        preg_match($pattern, $html, $matches);
        $config = json_decode(trim($matches[1]), true);

        $this->assertIsArray($config);
        $this->assertNotEmpty($config['ajaxUrl']);
        $this->assertNotEmpty($config['nonce']);
        $this->assertNotEmpty($config['challenge']);
        $this->assertNotEmpty($config['verify']);

        foreach (['unsupported', 'prompting', 'verifying', 'cancelled', 'failed'] as $key) {
            $this->assertNotEmpty($config['messages'][$key], $key . ' has no translated text');
        }
    }

    // ------------------------------------------------------------------- plumbing

    private function localizedConfig()
    {
        $data = (string)wp_scripts()->get_data('fluent_auth_login_helper', 'data');

        $this->assertNotEmpty($data, 'nothing was localized for the helper script');

        preg_match('#var fluentAuthPublic = (.*?);\s*$#s', $data, $matches);

        $decoded = json_decode($matches[1], true);

        $this->assertIsArray($decoded, 'the localized config is not valid JSON');

        return $decoded;
    }

    private function enablePasskeyLogin()
    {
        $this->setSettings([
            'passkey_2fa'           => 'yes',
            'passkey_2fa_roles'     => ['administrator'],
            'passkey_primary_login' => 'yes'
        ]);
    }

    /**
     * The `wp_login_form()` branch, which needs no login screen to be standing.
     *
     * @return string
     */
    private function renderPasskeyButton()
    {
        return (new PasskeyLoginHandler())->maybeRenderOnCustomForm('');
    }

    private function setSettings($settings)
    {
        update_option('__fls_auth_settings', array_merge(
            (array)get_option('__fls_auth_settings'),
            $settings
        ));

        Helper::resetStatics();
    }
}
