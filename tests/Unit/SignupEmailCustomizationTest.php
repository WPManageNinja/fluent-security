<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\CustomAuthHandler;
use FluentAuth\App\Hooks\Handlers\LoginCustomizerHandler;
use FluentAuth\App\Http\Controllers\SystemEmailsController;
use FluentAuth\App\Services\SystemEmailService;

/**
 * Preview defines a request-wide constant; isolate it from later real-delivery tests.
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class SignupEmailCustomizationTest extends BaseTestCase
{
    private $sent = [];
    private $catcher;

    public function setUp(): void
    {
        parent::setUp();
        delete_option('fa_system_email_settings');
        SystemEmailService::resetStatics();
        $_SERVER['REMOTE_ADDR'] = '192.0.2.197';
        Helper::resetStatics();
        $this->catcher = function ($return, $atts) {
            $this->sent[] = $atts;
            return true;
        };
        add_filter('pre_wp_mail', $this->catcher, 10, 2);
    }

    public function tearDown(): void
    {
        remove_filter('pre_wp_mail', $this->catcher, 10);
        remove_all_filters('fluent_auth/signup_verification_mail_subject');
        remove_all_filters('fluent_auth/signup_verification_email_body');
        delete_option('fa_system_email_settings');
        SystemEmailService::resetStatics();
        Helper::resetStatics();
        unset($_SERVER['REMOTE_ADDR']);
        wp_set_current_user(0);
        parent::tearDown();
    }

    private function request($params)
    {
        $request = new \WP_REST_Request('POST');
        $request->set_body_params(array_merge(['email_id' => 'signup_verification_to_user'], $params));
        return $request;
    }

    private function configure($settings)
    {
        update_option('fa_system_email_settings', ['emails' => ['signup_verification_to_user' => $settings]], false);
        SystemEmailService::resetStatics();
    }

    private function send($extra = [])
    {
        return (new CustomAuthHandler())->sendSignupEmailVerificationHtml(array_merge([
            'email' => 'signup-editor@example.test', 'first_name' => 'Jane',
        ], $extra));
    }

    public function test_editor_lists_a_separate_required_signup_template_without_account_tokens()
    {
        $result = SystemEmailsController::findEmail($this->request([]));
        $this->assertIsArray($result);
        $this->assertSame('Signup Verification Code Email', $result['email']['title']);
        $this->assertSame(['signup.verification_code'], $result['email']['required_smartcodes']);
        $this->assertNotSame('yes', $result['email']['can_disable'] ?? 'no');
        $this->assertSame('system', $result['settings']['status']);
        $this->assertStringContainsString('{{signup.verification_code}}', $result['default_content']['email']['body']);
        $codes = array_merge(...array_column($result['smartcodes'], 'shortcodes'));
        $this->assertArrayHasKey('{{signup.first_name}}', $codes);
        $this->assertArrayHasKey('##signup.verification_code##', $codes);
        $this->assertArrayHasKey('{{site.name}}', $codes);
        $this->assertArrayNotHasKey('{{user.roles}}', $codes);
        $this->assertArrayNotHasKey('{{user.user_email}}', $codes);
    }

    public function test_editor_requires_code_in_body()
    {
        $result = SystemEmailsController::saveEmailSettings($this->request(['settings' => [
            'status' => 'active', 'email' => ['subject' => '{{signup.verification_code}}', 'body' => '<p>No code</p>'],
        ]]));
        $this->assertWPError($result);
        $this->assertFalse(get_option('fa_system_email_settings'));

        foreach (['{{signup.verification_code}}', '##signup.verification_code##'] as $code) {
            $result = SystemEmailsController::saveEmailSettings($this->request(['settings' => [
                'status' => 'active', 'email' => ['subject' => 'Confirm signup', 'body' => '<p>' . $code . '</p>'],
            ]]));
            $this->assertIsArray($result);
            SystemEmailService::resetStatics();
            $this->assertSame('active', SystemEmailService::getEmailSettingsByType('signup_verification_to_user')['status']);
        }
    }

    public function test_preview_uses_sample_signup_values_without_sending_or_creating_a_challenge()
    {
        $admin = $this->factory->user->create(['role' => 'administrator', 'first_name' => 'PrivateAdmin']);
        wp_set_current_user($admin);
        $before = flsDb()->table('fls_login_hashes')->count();
        $result = SystemEmailsController::previewEmail($this->request(['email_data' => [
            'subject' => '{{signup.first_name}} {{signup.verification_code}} {{user.first_name}}',
            'body' => '<p>{{signup.first_name}} {{signup.last_name}} {{signup.email}} {{signup.username}} ##signup.verification_code## {{user.first_name}}</p>',
        ]]));
        $this->assertIsArray($result);
        $this->assertStringContainsString('Sample 123456', $result['rendered_email']['subject']);
        $this->assertStringContainsString('sample@example.test', $result['rendered_email']['body']);
        $this->assertStringNotContainsString('PrivateAdmin', implode(' ', $result['rendered_email']));
        $this->assertStringNotContainsString('{{signup.', $result['rendered_email']['body']);
        $this->assertCount(0, $this->sent);
        $this->assertSame($before, flsDb()->table('fls_login_hashes')->count());
    }

    public function test_saving_and_resetting_signup_preserves_legacy_emails_and_template_settings()
    {
        $legacy = ['emails' => ['magic_email_to_user' => ['status' => 'active', 'email' => ['subject' => 'Old magic', 'body' => 'Old body']]], 'template_settings' => ['content_bg' => '#fafafa']];
        update_option('fa_system_email_settings', $legacy, false);
        SystemEmailService::resetStatics();
        foreach (['active', 'system'] as $status) {
            $result = SystemEmailsController::saveEmailSettings($this->request(['settings' => [
                'status' => $status, 'email' => ['subject' => 'New signup', 'body' => '{{signup.verification_code}}'],
            ]]));
            $this->assertIsArray($result);
            SystemEmailService::resetStatics();
            $saved = get_option('fa_system_email_settings');
            $this->assertSame($legacy['emails']['magic_email_to_user'], $saved['emails']['magic_email_to_user']);
            $this->assertSame('#fafafa', $saved['template_settings']['content_bg']);
        }
    }

    public function test_custom_signup_reaches_real_mail_with_escaped_pre_account_data_and_matching_code()
    {
        $this->configure(['status' => 'active', 'email' => [
            'subject' => 'Signup {{signup.first_name}} {{signup.last_name}} {{signup.username}}',
            'body' => '<p>Custom {{signup.first_name}} {{signup.last_name}} {{signup.email}} {{signup.username}} ##signup.verification_code## {{user.user_email}}</p>',
        ]]);
        $rawBody = '';
        add_filter('fluent_auth/signup_verification_email_body', function ($body) use (&$rawBody) {
            $rawBody = $body;
            return $body;
        });
        $form = ['first_name' => wp_slash("O'Brien <b>語</b> {{site.admin_email}}"), 'last_name' => 'Last', 'username' => 'signup_user'];
        $html = $this->send($form);
        $this->assertStringContainsString('fls_signup_verification', $html);
        $this->assertCount(1, $this->sent);
        $mail = $this->sent[0];
        $this->assertSame('signup-editor@example.test', $mail['to']);
        $this->assertStringContainsString("Signup O'Brien 語 {{site.admin_email}} Last signup_user", $mail['subject']);
        $this->assertStringContainsString('Custom O&#039;Brien 語 {{site.admin_email}}', $rawBody);
        $this->assertStringContainsString("Custom O'Brien 語 {{site.admin_email}}", $mail['message']);
        $this->assertStringNotContainsString('<b>語</b>', $mail['message']);
        $this->assertStringNotContainsString('{{user.user_email}}', $mail['message']);
        $this->assertStringContainsString('content_wrap', $mail['message']);
        $this->assertMatchesRegularExpression('/signup_user ([0-9]{6})/', $mail['message']);
        preg_match('/signup_user ([0-9]{6})/', $mail['message'], $matches);
        $row = flsDb()->table('fls_login_hashes')->where('use_type', 'signup_verification')->first();
        $this->assertTrue(wp_check_password($matches[1] . '|signup-editor@example.test', $row->two_fa_code_hash));
        $this->assertFalse(get_user_by('email', $mail['to']));
    }

    public function test_signup_filters_keep_arguments_and_override_both_default_and_custom_content_once()
    {
        foreach (['system', 'active'] as $status) {
            $this->configure(['status' => $status, 'email' => ['subject' => 'Custom subject', 'body' => '<p>Custom {{signup.verification_code}}</p>']]);
            $calls = [];
            $subject = function ($value) use (&$calls) { $calls[] = ['subject', $value]; return 'Filtered subject'; };
            $body = function ($value, $code, $data) use (&$calls) {
                $calls[] = ['body', $value, $code, $data];
                return '<p>Filtered body ' . $code . '</p>';
            };
            add_filter('fluent_auth/signup_verification_mail_subject', $subject);
            add_filter('fluent_auth/signup_verification_email_body', $body, 10, 3);
            $this->send();
            remove_filter('fluent_auth/signup_verification_mail_subject', $subject);
            remove_filter('fluent_auth/signup_verification_email_body', $body);
            $this->assertCount(2, $calls);
            $this->assertSame('signup-editor@example.test', $calls[1][3]['email']);
            $this->assertIsString($calls[1][2]);
            $this->assertSame('Filtered subject', end($this->sent)['subject']);
            $this->assertStringContainsString('Filtered body ' . $calls[1][2], end($this->sent)['message']);
            $this->assertStringNotContainsString('<html', $calls[1][1]);
            if ($status === 'active') {
                $this->assertSame('Custom subject', $calls[0][1]);
                $this->assertStringContainsString('Custom ' . $calls[1][2], $calls[1][1]);
            }
        }
    }

    public function test_native_registration_supplies_the_username_to_the_signup_template()
    {
        global $wp_actions;
        $actions = $wp_actions;
        try {
            // Exercise this handler's deferred callback without unrelated page renderers.
            remove_all_actions('register_form');
            $wp_actions['login_init'] = 1;
            unset($wp_actions['fluent_auth/after_signup_validation']);
            update_option('__fls_auth_settings', ['secure_signup_form' => 'yes']);
            Helper::resetStatics();
            $_POST = ['user_full_name' => 'Native Signup', 'user_password' => 'fixture-pass', 'user_confirm_password' => 'fixture-pass', 'agree_terms' => 'agreed'];
            $this->configure(['status' => 'active', 'email' => [
                'subject' => 'Native {{signup.username}}',
                'body' => '<p>Native ##signup.username## {{signup.verification_code}}</p>',
            ]]);
            $errors = (new LoginCustomizerHandler())->maybeInterceptRegistration(new \WP_Error(), 'native_signup_23297', 'native-signup@example.test');
            ob_start();
            do_action('register_form');
            $html = ob_get_clean();
        } finally {
            $wp_actions = $actions;
            $_POST = [];
            delete_option('__fls_auth_settings');
            remove_all_actions('register_form');
            remove_all_actions('login_body_class');
        }
        $this->assertSame(['confirm_token'], $errors->get_error_codes());
        $this->assertStringContainsString('fls_signup_verification', $html);
        $this->assertCount(1, $this->sent);
        $this->assertSame('Native native_signup_23297', $this->sent[0]['subject']);
        $this->assertStringContainsString('Native native_signup_23297', $this->sent[0]['message']);
        $this->assertFalse(get_user_by('email', 'native-signup@example.test'));
    }

    /** @dataProvider fallbackSettings */
    public function test_missing_invalid_and_disabled_settings_keep_the_builtin_verification_email($settings)
    {
        $this->configure($settings);
        $this->send(['first_name' => wp_slash("O'Brien")]);
        $this->assertCount(1, $this->sent);
        $this->assertStringContainsString('Your registration verification code for', $this->sent[0]['subject']);
        $this->assertStringContainsString('Hello O&#039;Brien,', $this->sent[0]['message']);
        $this->assertStringContainsString('Verification Code:', $this->sent[0]['message']);
        $this->assertStringContainsString('10 minutes', $this->sent[0]['message']);
    }

    public static function fallbackSettings()
    {
        return [
            'missing' => [[]], 'malformed' => ['invalid'],
            'disabled' => [['status' => 'disabled']],
            'no code' => [['status' => 'active', 'email' => ['subject' => 'Custom', 'body' => 'No code']]],
            'empty subject' => [['status' => 'active', 'email' => ['subject' => '', 'body' => '{{signup.verification_code}}']]],
            'malformed body' => [['status' => 'active', 'email' => ['subject' => 'Custom', 'body' => ['{{signup.verification_code}}']]]],
        ];
    }
}
