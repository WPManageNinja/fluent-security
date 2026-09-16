<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;

class HelperTest extends BaseTestCase
{
    public function testGetAuthSettings()
    {
        update_option('__fls_auth_settings', [
            'disable_xmlrpc' => 'no',
            'enable_auth_logs' => 'yes',
            'login_try_limit' => 5,
            'login_try_timing' => 30,
            'auto_delete_logs_day' => 30
        ]);

        $settings = Helper::getAuthSettings();

        $this->assertIsArray($settings);
        $this->assertArrayHasKey('disable_xmlrpc', $settings);
        $this->assertArrayHasKey('login_try_limit', $settings);
        $this->assertArrayHasKey('login_try_timing', $settings);
        $this->assertEquals('no', $settings['disable_xmlrpc']);
        $this->assertEquals(5, $settings['login_try_limit']);
        $this->assertEquals(30, $settings['login_try_timing']);
    }

    /**
     * With no option set these are the defaults, and nothing more - a site that has not
     * been configured is told apart by the absence of the option itself, so the defaults
     * carry no flag saying so. See Onboarding::isRequired().
     */
    public function testGetAuthSettingsDefaults()
    {
        $settings = Helper::getAuthSettings();

        $this->assertIsArray($settings);
        $this->assertArrayHasKey('disable_xmlrpc', $settings);
        $this->assertArrayNotHasKey('require_configuration', $settings);
        $this->assertEquals('monthly', $settings['digest_summary']);
    }

    public function testGetAppPermission()
    {
        $permission = Helper::getAppPermission();
        $this->assertEquals('manage_options', $permission);
    }

    public function testGetUserRoles()
    {
        $roles = Helper::getUserRoles(true);
        $this->assertIsArray($roles);
        $this->assertArrayHasKey('administrator', $roles);
        $this->assertArrayHasKey('editor', $roles);
        $this->assertArrayHasKey('subscriber', $roles);

        Helper::resetStatics();
        $roles = Helper::getUserRoles(false);
        $this->assertIsArray($roles);
        $this->assertIsArray($roles[0]);
        $this->assertArrayHasKey('id', $roles[0]);
        $this->assertArrayHasKey('title', $roles[0]);
    }

    public function testGetLowLevelRoles()
    {
        $roles = Helper::getLowLevelRoles();
        $this->assertIsArray($roles);
        $this->assertArrayHasKey('subscriber', $roles);
        $this->assertArrayNotHasKey('administrator', $roles);
        $this->assertArrayNotHasKey('editor', $roles);
    }

    public function testGetWpPermissions()
    {
        $permissions = Helper::getWpPermissions(true);
        $this->assertIsArray($permissions);
        $this->assertArrayHasKey('manage_options', $permissions);
        $this->assertArrayHasKey('publish_posts', $permissions);
        $this->assertArrayHasKey('read', $permissions);

        $permissions = Helper::getWpPermissions(false);
        $this->assertIsArray($permissions);
        $this->assertIsArray($permissions[0]);
        $this->assertArrayHasKey('id', $permissions[0]);
        $this->assertArrayHasKey('title', $permissions[0]);
    }

    public function testGetSetting()
    {
        update_option('__fls_auth_settings', [
            'disable_xmlrpc' => 'no',
            'enable_auth_logs' => 'yes',
        ]);

        $setting = Helper::getSetting('disable_xmlrpc');
        $this->assertEquals('no', $setting);

        $setting = Helper::getSetting('non_existing', 'default_value');
        $this->assertEquals('default_value', $setting);
    }

    public function testGetIp()
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';

        $ip = Helper::getIp();
        $this->assertNotEmpty($ip);
    }

    public function testLoadView()
    {
        $data = ['title' => 'Test Title'];
        $result = Helper::loadView('nonexistent_template', $data);
        $this->assertIsString($result);
    }

    public function testCleanUpLogs()
    {
        update_option('__fls_auth_settings', [
            'auto_delete_logs_day' => 30,
            'enable_auth_logs' => 'yes',
        ]);

        $result = Helper::cleanUpLogs();
        $this->assertNull($result);
    }

    public function testGetSocialAuthSettings()
    {
        $settings = Helper::getSocialAuthSettings();

        $this->assertIsArray($settings);
        $this->assertArrayHasKey('enabled', $settings);
        $this->assertArrayHasKey('enable_google', $settings);
        $this->assertArrayHasKey('google_client_id', $settings);
        $this->assertEquals('no', $settings['enabled']);
        $this->assertEquals('no', $settings['enable_google']);
    }

    public function testGetAuthFormsSettings()
    {
        $settings = Helper::getAuthFormsSettings();

        $this->assertIsArray($settings);
        $this->assertArrayHasKey('enabled', $settings);
        $this->assertArrayHasKey('login_redirects', $settings);
        $this->assertEquals('no', $settings['enabled']);
        $this->assertEquals('no', $settings['login_redirects']);
    }

    public function testSetAndGetLoginMedia()
    {
        Helper::setLoginMedia('api');
        $media = Helper::getLoginMedia();
        $this->assertEquals('api', $media);
    }

    public function testGetAuthCustomizerSettings()
    {
        $settings = Helper::getAuthCustomizerSettings();

        $this->assertIsArray($settings);
        $this->assertArrayHasKey('login', $settings);
        $this->assertArrayHasKey('signup', $settings);
        $this->assertArrayHasKey('status', $settings);

        $this->assertArrayHasKey('banner', $settings['login']);
        $this->assertArrayHasKey('form', $settings['login']);

        $this->assertArrayHasKey('title', $settings['login']['banner']);
        $this->assertArrayHasKey('description', $settings['login']['banner']);
    }

    public function testFormatAuthCustomizerSettings()
    {
        $settings = [
            'login' => [
                'banner' => [
                    'title' => 'Test Title <script>alert(1)</script>',
                    'description' => 'Test Description',
                    'hidden' => true
                ],
                'form' => [
                    'title' => 'Form Title',
                    'button_label' => 'Login',
                    'button_color' => '#ff0000',
                    'background_image' => 'http://example.com/image.jpg',
                    'background_color' => '#ffffff'
                ]
            ]
        ];

        $formatted = Helper::formatAuthCustomizerSettings($settings);

        $this->assertIsArray($formatted);
        $this->assertStringNotContainsString('<script>', $formatted['login']['banner']['title']);
        $this->assertTrue($formatted['login']['banner']['hidden']);
    }

    /**
     * The customizer's colours are interpolated into a `:root { ... }` block on
     * wp-login.php. sanitize_text_field() leaves `{`, `}` and `;` alone, so a value that is
     * not a colour was a way to write a stylesheet onto the site's sign-in page.
     *
     * Only an administrator can save these, which is why this is a guard rather than a
     * hole - but the capability those screens require is itself filterable, and a site that
     * lowers it should not be handing out the login page along with the settings page.
     */
    public function testCustomizerColoursAreColoursOrNothing()
    {
        $settings = [
            'login' => [
                'banner' => [
                    'title_color'      => 'red } body { background: url(https://evil.test/x) } x {',
                    'text_color'       => '#ffffff',
                    'background_color' => 'rgba(155, 81, 224, 1)',
                    'button_color'     => 'expression(alert(1))',
                    'description'      => 'fine'
                ]
            ]
        ];

        $formatted = Helper::formatAuthCustomizerSettings($settings);
        $banner = $formatted['login']['banner'];

        $this->assertSame('', $banner['title_color'], 'a declaration dressed as a colour is dropped');
        $this->assertSame('', $banner['button_color']);

        /* And every form the colour picker actually produces still survives untouched. */
        $this->assertSame('#ffffff', $banner['text_color']);
        $this->assertSame('rgba(155, 81, 224, 1)', $banner['background_color']);
    }

    public function testEveryShapeOfColourThePickerProducesIsKept()
    {
        foreach (['#fff', '#ffffff', '#ffffffcc', 'rgb(1,2,3)', 'rgba(1,2,3,0.5)', 'hsl(120 50% 50%)', 'transparent', 'rebeccapurple'] as $value) {
            $this->assertSame($value, Helper::sanitizeCssColor($value), $value);
        }
    }

    public function testNothingThatCouldCloseTheDeclarationSurvives()
    {
        foreach ([
            '#fff;background:url(x)',
            'red;}',
            'url(javascript:alert(1))',
            '}*{display:none',
            'var(--x);color:red',
            '#fff/*',
            "#fff\n}"
        ] as $value) {
            $this->assertSame('', Helper::sanitizeCssColor($value), $value);
        }
    }

    public function testGetValidatedRedirectUrl()
    {
        $result = Helper::getValidatedRedirectUrl(admin_url(), '/fallback');
        $this->assertNotEmpty($result);

        $result = Helper::getValidatedRedirectUrl('http://evil.com', '/fallback');
        $this->assertEquals('/fallback', $result);
    }
}
