<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\GoogleOneTapAuthHandler;

/**
 * Google draws the "Continue with Google" button in the language of the visitor's
 * Google account or location unless the page names one. The button follows the
 * site's language, handed to one_tap.js in fluentOneTapConfig.locale.
 */
class GoogleOneTapLocaleTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        update_option('__fls_social_auth_settings', [
            'google_key_method'    => 'db',
            'google_client_id'     => '1234567890-test.apps.googleusercontent.com',
            'google_client_secret' => 'secret',
            'enable_google'        => 'yes',
            'google_one_tap'       => 'yes',
        ]);
        Helper::resetStatics();
        wp_dequeue_script('fluent-auth-google-one-tap');
        wp_deregister_script('fluent-auth-google-one-tap');
    }

    public function tearDown(): void
    {
        remove_all_filters('locale');
        wp_deregister_script('fluent-auth-google-one-tap');
        parent::tearDown();
    }

    private function oneTapConfig()
    {
        (new GoogleOneTapAuthHandler())->fluentAuthOneTabloadAssets(['type' => 'inline', 'delay' => 2]);

        $data = (string)wp_scripts()->get_data('fluent-auth-google-one-tap', 'data');
        $this->assertMatchesRegularExpression('/var fluentOneTapConfig = (\{.*\});/s', $data);
        preg_match('/var fluentOneTapConfig = (\{.*\});/s', $data, $m);

        return json_decode($m[1], true);
    }

    public function test_button_language_is_the_site_language()
    {
        $this->assertSame(determine_locale(), $this->oneTapConfig()['locale']);
    }

    public function test_button_language_follows_a_site_in_another_language()
    {
        add_filter('locale', function () {
            return 'de_DE';
        });

        $this->assertSame('de_DE', $this->oneTapConfig()['locale']);
    }
}
