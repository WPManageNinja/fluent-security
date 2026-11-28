<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\LoginCustomizerHandler;

/**
 * The login customizer's banner column, as wp-login.php prints it.
 *
 * "Hide banner" was saved and honoured by the editor's preview, but the login page
 * printed the banner anyway: neither the login_header nor the login_footer callback
 * read banner.hidden.
 */
class LoginCustomizerBannerTest extends BaseTestCase
{
    private $savedHooks = [];

    public function setUp(): void
    {
        parent::setUp();

        global $wp_filter;
        foreach (['login_header', 'login_footer', 'login_enqueue_scripts'] as $hook) {
            $this->savedHooks[$hook] = isset($wp_filter[$hook]) ? clone $wp_filter[$hook] : null;
            remove_all_actions($hook);
        }
    }

    public function tearDown(): void
    {
        global $wp_filter;
        foreach ($this->savedHooks as $hook => $saved) {
            if ($saved) {
                $wp_filter[$hook] = $saved;
            } else {
                unset($wp_filter[$hook]);
            }
        }

        remove_all_filters('fluent_auth/extra_login_page_wrap_css_class');
        delete_option('__fls_auth_customizer_settings');

        parent::tearDown();
    }

    private function saveBanner($formType, array $banner)
    {
        $settings = Helper::getAuthCustomizerSettings();
        $settings['status'] = 'yes';
        $settings[$formType]['banner'] = array_merge($settings[$formType]['banner'], $banner);

        update_option('__fls_auth_customizer_settings', $settings, false);
    }

    /**
     * What the customized wp-login.php screen prints around the form.
     */
    private function renderScreen($action, $formType)
    {
        $method = new \ReflectionMethod(LoginCustomizerHandler::class, 'loadCustomizedDesign');
        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }
        $method->invoke(new LoginCustomizerHandler(), $action, $formType);

        ob_start();
        do_action('login_header');
        do_action('login_footer');

        return ob_get_clean();
    }

    public function test_a_shown_banner_is_printed_beside_the_form()
    {
        $this->saveBanner('login', ['title' => 'Shown banner title', 'position' => 'left']);

        $html = $this->renderScreen('login', 'login');

        $this->assertStringContainsString('fls_login_cusom_content_wrap', $html);
        $this->assertStringContainsString('Shown banner title', $html);
        $this->assertStringContainsString('fls_layout_banner_left', $html);
    }

    public function test_a_hidden_banner_is_not_printed_on_the_login_screen()
    {
        $this->saveBanner('login', [
            'hidden'           => true,
            'title'            => 'Hidden banner title',
            'background_image' => 'https://example.test/banner.jpg',
        ]);

        $html = $this->renderScreen('login', 'login');

        $this->assertStringNotContainsString('fls_login_cusom_content_wrap', $html);
        $this->assertStringNotContainsString('Hidden banner title', $html);
        $this->assertStringNotContainsString('banner.jpg', $html);
        $this->assertStringNotContainsString('fls_layout_banner_', $html, 'no banner layout class without a banner');
        $this->assertStringContainsString('fls_login_form_wrap', $html, 'the form is still printed');
    }

    public function test_a_hidden_banner_is_not_printed_on_the_signup_screen()
    {
        $this->saveBanner('signup', ['hidden' => true, 'title' => 'Hidden signup banner']);

        $html = $this->renderScreen('register', 'signup');

        $this->assertStringNotContainsString('fls_login_cusom_content_wrap', $html);
        $this->assertStringNotContainsString('Hidden signup banner', $html);
    }

    /**
     * The lost-password screen has no settings of its own and borrows the login form's.
     */
    public function test_the_lost_password_screen_follows_the_login_forms_hidden_banner()
    {
        $this->saveBanner('login', ['hidden' => true, 'title' => 'Hidden login banner']);

        $html = $this->renderScreen('lostpassword', 'reset_password');

        $this->assertStringNotContainsString('fls_login_cusom_content_wrap', $html);
        $this->assertStringNotContainsString('Hidden login banner', $html);
    }

    /**
     * Colours are checked on save only since 3.0.2, so a value saved before then reaches
     * the page as it was typed until the customizer is saved again.
     */
    public function test_a_colour_that_is_not_a_colour_never_reaches_the_inline_css()
    {
        $settings = Helper::getAuthCustomizerSettings();
        $settings['status'] = 'yes';
        $settings['login']['banner']['title_color'] = 'red } body { background: url(https://evil.test/x) } x {';
        $settings['login']['banner']['background_image'] = 'https://example.test/banner.jpg';
        $settings['login']['form']['title_color'] = '#123456';
        update_option('__fls_auth_customizer_settings', $settings, false);

        $this->renderScreen('login', 'login');
        wp_enqueue_style('fls-login-customizer', 'https://example.test/login_customizer.css');
        do_action('login_enqueue_scripts');
        $css = implode("\n", (array)wp_styles()->get_data('fls-login-customizer', 'after'));
        wp_dequeue_style('fls-login-customizer');
        wp_deregister_style('fls-login-customizer');

        $this->assertStringNotContainsString('evil.test', $css);
        $this->assertStringNotContainsString('}', substr($css, 0, -1), 'only the :root block closes');
        $this->assertStringNotContainsString('banner.jpg', $css, 'image URLs are not CSS variables');
        $this->assertStringContainsString('--fls-form-title_color: #123456;', $css, 'a real colour still goes through');
    }

    /**
     * What wp-login.php prints for a request, going through the same dispatch it does:
     * maybeCustomizeAuthPage() on login_init, then the header and footer hooks.
     */
    private function renderRequest(array $get, array $post = [])
    {
        $_GET = $get;
        $_POST = $post;
        $_REQUEST = array_merge($get, $post);

        try {
            (new LoginCustomizerHandler())->maybeCustomizeAuthPage();

            ob_start();
            do_action('login_header');
            do_action('login_footer');

            return ob_get_clean();
        } finally {
            $_GET = $_POST = $_REQUEST = [];
        }
    }

    public function screensWithTheirOwnWords()
    {
        // request, form type, heading shown when nothing is saved for the type
        return [
            'reset link (rp with a key)'      => [['action' => 'rp', 'key' => 'abc', 'login' => 'someone'], [], 'new_password', 'Choose a new password'],
            'new password form (resetpass)'   => [['action' => 'resetpass'], [], 'new_password', 'Choose a new password'],
            'password has been reset'         => [['action' => 'resetpass'], ['pass1' => 'New-Pass-123', 'pass2' => 'New-Pass-123'], 'new_password', ''],
            'check your email'                => [['checkemail' => 'confirm'], [], 'check_email', ''],
            'personal-data request confirmed' => [['action' => 'confirmaction', 'request_id' => '1'], [], 'confirmaction', ''],
            'confirm the admin email'         => [['action' => 'confirm_admin_email'], [], 'confirm_admin_email', ''],
            'two-factor login code'           => [['action' => 'fls_2fa_verify'], [], 'two_fa_verify', ''],
        ];
    }

    /**
     * These screens used to fall through to the login form, so they printed
     * "Login to <site>" and "Please enter your details to login".
     *
     * @dataProvider screensWithTheirOwnWords
     */
    public function test_a_screen_that_is_not_the_login_form_does_not_use_its_words($get, $post, $expectedType, $expectedTitle)
    {
        $this->saveBanner('login', []);

        $html = $this->renderRequest($get, $post);

        $this->assertStringContainsString('fls_form_type_' . $expectedType, $html);
        $this->assertStringNotContainsString('Please enter your details to login', $html);
        $this->assertStringNotContainsString('Login to ', $html);
        $this->assertMatchesRegularExpression('#<h1>' . preg_quote($expectedTitle, '#') . '</h1>#', $html);
    }

    /**
     * A host that overrides the settings can give a screen its own words by its type.
     */
    public function test_saved_settings_for_a_screens_type_are_used()
    {
        $settings = Helper::getAuthCustomizerSettings();
        $settings['status'] = 'yes';
        $settings['new_password'] = $settings['login'];
        $settings['new_password']['form'] = ['title' => 'Pick a fresh password'];
        update_option('__fls_auth_customizer_settings', $settings, false);

        $html = $this->renderRequest(['action' => 'rp', 'key' => 'abc', 'login' => 'someone']);

        $this->assertStringContainsString('<h1>Pick a fresh password</h1>', $html);
        $this->assertStringContainsString('<p></p>', $html, 'a missing description prints nothing');
    }

    public function test_the_login_form_keeps_its_own_words()
    {
        $this->saveBanner('login', []);

        $html = $this->renderRequest([]);

        $this->assertStringContainsString('fls_form_type_login', $html);
        $this->assertStringContainsString('Please enter your details to login', $html);
    }

    public function test_a_class_from_the_wrapper_filter_stays_a_separate_class()
    {
        $this->saveBanner('login', ['position' => 'left']);
        add_filter('fluent_auth/extra_login_page_wrap_css_class', function () {
            return 'my_class';
        });

        $html = $this->renderScreen('login', 'login');

        $this->assertMatchesRegularExpression('/class="[^"]*\bmy_class fls_layout_banner_left\b/', $html);
    }
}
