<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\SettingsController;

class SettingsControllerTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        update_option('__fls_auth_settings', [
            'disable_xmlrpc' => 'no',
            'enable_auth_logs' => 'yes',
            'login_try_limit' => 5,
            'login_try_timing' => 30,
            'auto_delete_logs_day' => 30,
            'disable_app_login' => 'no',
            'disable_users_rest' => 'no',
            'secure_signup_form' => 'yes',
            'notification_user_roles' => [],
            'notify_on_blocked' => 'no',
            'notification_email' => '{admin_email}',
            'digest_summary' => '',
            'magic_login' => 'no',
            'magic_restricted_roles' => [],
            'magic_link_primary' => 'no',
            'email2fa' => 'no',
            'email2fa_roles' => ['administrator', 'editor', 'author'],
            'disable_admin_bar' => 'no',
            'disable_bar_roles' => ['subscriber'],
        ]);

        update_option('__fls_auth_forms_settings', [
            'enabled' => 'no',
            'login_redirects' => 'no',
            'default_login_redirect' => '',
            'default_logout_redirect' => '',
            'redirect_rules' => []
        ]);
    }

    public function testGetSettings()
    {
        $request = new \WP_REST_Request();

        $result = SettingsController::getSettings($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('settings', $result);
        $this->assertArrayHasKey('user_roles', $result);
        $this->assertArrayHasKey('low_level_roles', $result);
    }

    public function testUpdateSettings()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'disable_xmlrpc' => 'yes',
            'enable_auth_logs' => 'yes',
            'login_try_limit' => 10,
            'login_try_timing' => 30,
            'email2fa' => 'no',
            'email2fa_roles' => [],
        ]);

        $result = SettingsController::updateSettings($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('message', $result);
    }

    public function testUpdateSettingsInvalidData()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'enable_auth_logs' => 'yes',
            'login_try_limit' => 0,
            'login_try_timing' => 0,
            'email2fa' => 'no',
        ]);

        $result = SettingsController::updateSettings($request);

        $this->assertInstanceOf(\WP_Error::class, $result);
    }

    public function testGetAuthFormSettings()
    {
        $request = new \WP_REST_Request();

        $result = SettingsController::getAuthFormSettings($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('settings', $result);
    }

    public function testSaveAuthFormSettings()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'enabled' => 'yes',
        ]);

        $result = SettingsController::saveAuthFormSettings($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('message', $result);
    }

    public function testGetAuthCustomizerSetting()
    {
        $request = new \WP_REST_Request();

        $result = SettingsController::getAuthCustomizerSetting($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('settings', $result);
    }

    public function testSaveAuthCustomizerSetting()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'login' => [
                'banner' => [
                    'title' => 'Test Title',
                    'hidden' => false,
                    'description' => 'Test Desc',
                ]
            ]
        ]);

        $result = SettingsController::saveAuthCustomizerSetting($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('message', $result);
    }

    public function testUploadImageNoFile()
    {
        $request = new \WP_REST_Request();
        $_FILES = ['file' => []];

        $result = SettingsController::uploadImage($request);

        $this->assertInstanceOf(\WP_Error::class, $result);

        $_FILES = [];
    }

    public function testUpdateSettingsWithSocialLogin()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'enable_auth_logs' => 'yes',
            'login_try_limit' => 5,
            'login_try_timing' => 30,
            'email2fa' => 'no',
            'email2fa_roles' => [],
        ]);

        $result = SettingsController::updateSettings($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('message', $result);
    }

    public function testGetSettingsWithPermissions()
    {
        $request = new \WP_REST_Request();

        $result = SettingsController::getSettings($request);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('settings', $result);
        $this->assertArrayHasKey('disable_xmlrpc', $result['settings']);
        $this->assertArrayHasKey('login_try_limit', $result['settings']);
        $this->assertArrayHasKey('login_try_timing', $result['settings']);
    }

    // ------------------------------- keeping roles out of wp-admin

    /*
     * The screen offers one setting for this - the list of roles. The `disable_admin_bar`
     * switch it used to also offer is derived from that list now, because the two saying
     * different things was a state with no meaning: both handlers return early on an
     * empty list, so "switched on, nobody chosen" already did nothing.
     */
    private function saveWithBarRoles($roles, $switch = null)
    {
        $payload = [
            'login_try_limit'   => 5,
            'login_try_timing'  => 30,
            'email2fa'          => 'no',
            'email2fa_roles'    => [],
            'disable_bar_roles' => $roles,
        ];

        if ($switch !== null) {
            $payload['disable_admin_bar'] = $switch;
        }

        $request = new \WP_REST_Request();
        $request->set_param('settings', $payload);

        return SettingsController::updateSettings($request);
    }

    private function saveWithDigest($frequency)
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'login_try_limit'  => 5,
            'login_try_timing' => 30,
            'email2fa'         => 'no',
            'email2fa_roles'   => [],
            'digest_summary'   => $frequency,
        ]);

        return SettingsController::updateSettings($request);
    }

    public function testChangingTheDigestFrequencyStartsAFreshWindow()
    {
        $this->saveWithDigest('daily');
        update_option('_fls_last_digest_sent', '2026-09-09 08:00:00', false);

        // Saving again with the same frequency keeps the window.
        \FluentAuth\App\Helpers\Helper::resetStatics();
        $this->saveWithDigest('daily');
        $this->assertSame('2026-09-09 08:00:00', get_option('_fls_last_digest_sent'));

        // A different one would otherwise be gated by a daily send a few days ago.
        \FluentAuth\App\Helpers\Helper::resetStatics();
        $this->saveWithDigest('mon');
        $this->assertFalse(get_option('_fls_last_digest_sent'));
    }

    public function testChoosingRolesTurnsTheRestrictionOn()
    {
        $result = $this->saveWithBarRoles(['subscriber']);

        $this->assertEquals('yes', $result['settings']['disable_admin_bar']);
        $this->assertEquals(['subscriber'], $result['settings']['disable_bar_roles']);
    }

    public function testClearingTheRolesTurnsItOff()
    {
        $result = $this->saveWithBarRoles([]);

        $this->assertEquals('no', $result['settings']['disable_admin_bar']);
    }

    public function testTheSwitchCannotContradictTheRoleList()
    {
        // Claiming it is on with nobody chosen never did anything; it is stored as off.
        $this->assertEquals('no', $this->saveWithBarRoles([], 'yes')['settings']['disable_admin_bar']);

        // And the reverse: roles chosen means on, whatever an older client sends.
        $this->assertEquals('yes', $this->saveWithBarRoles(['subscriber'], 'no')['settings']['disable_admin_bar']);
    }

    /*
     * An emptied multi-select posts an empty string, not an empty array. Every reader
     * happens to test the value for truth first, so nothing breaks on it today - but a
     * list setting should hold a list.
     */
    public function testAnEmptiedRoleListIsStoredAsAnArray()
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', [
            'login_try_limit'         => 5,
            'login_try_timing'        => 30,
            'email2fa'                => 'no',
            'email2fa_roles'          => '',
            'disable_bar_roles'       => '',
            'notification_user_roles' => '',
        ]);

        $settings = SettingsController::updateSettings($request)['settings'];

        $this->assertSame([], $settings['disable_bar_roles']);
        $this->assertSame([], $settings['email2fa_roles']);
        $this->assertSame([], $settings['notification_user_roles']);
    }
}
