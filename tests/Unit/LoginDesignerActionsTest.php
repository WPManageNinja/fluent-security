<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\LoginCustomizerHandler;

/**
 * Login screens other plugins add to wp-login.php (filter
 * fluent_auth/login_designer_actions) are dressed like the plugin's own.
 *
 * Before the filter, the designer dressed a fixed list of actions, so a
 * consent screen on wp-login.php?action=<its own> showed bare WordPress in
 * the middle of a site that had dressed its login page.
 */
class LoginDesignerActionsTest extends BaseTestCase
{
    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/login_designer_actions');
        unset($_REQUEST['action'], $_GET['action']);

        parent::tearDown();
    }

    private function currentAction($action)
    {
        $_REQUEST['action'] = $action;
        $method = new \ReflectionMethod(LoginCustomizerHandler::class, 'getCurrentAction');
        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }

        return $method->invoke(new LoginCustomizerHandler());
    }

    public function test_an_unknown_action_is_not_dressed()
    {
        $this->assertSame('', $this->currentAction('connect_ai'));
    }

    public function test_an_added_action_is_dressed_with_its_form_type()
    {
        add_filter('fluent_auth/login_designer_actions', function ($actions) {
            $actions['connect_ai'] = 'ai_connect';

            return $actions;
        });

        $this->assertSame('connect_ai', $this->currentAction('connect_ai'));
        $this->assertSame('ai_connect', (new LoginCustomizerHandler())->getFormType('connect_ai'));
    }

    public function test_the_plugins_own_actions_keep_their_form_types()
    {
        add_filter('fluent_auth/login_designer_actions', function ($actions) {
            $actions['register'] = 'not_signup';

            return $actions;
        });

        $this->assertSame('signup', (new LoginCustomizerHandler())->getFormType('register'));
        $this->assertSame('login', (new LoginCustomizerHandler())->getFormType('login'));
    }

    public function test_invalid_entries_are_ignored()
    {
        add_filter('fluent_auth/login_designer_actions', function () {
            return [
                'Bad Action' => 'login',
                'ok_action'  => 'Bad Type!',
                7            => 'login',
                'fine'       => 'fine_type',
            ];
        });

        $this->assertSame(['fine' => 'fine_type'], LoginCustomizerHandler::extraActions());
    }

    public function test_an_array_action_is_not_dressed_and_does_not_fail()
    {
        add_filter('fluent_auth/login_designer_actions', function ($actions) {
            $actions['connect_ai'] = 'ai_connect';

            return $actions;
        });

        $this->assertSame('', $this->currentAction(['x']));
    }

    /**
     * `status` is the designer's on/off switch, not a form. A screen whose
     * form type has that name gets the login form's look, not a fatal error.
     */
    public function test_a_form_type_named_like_a_setting_renders_with_the_login_look()
    {
        $settings = \FluentAuth\App\Helpers\Helper::getAuthCustomizerSettings();
        $settings['status'] = 'yes';
        $settings['login']['banner']['title'] = 'Login banner title';
        update_option('__fls_auth_customizer_settings', $settings, false);

        global $wp_filter;
        $saved = [];
        foreach (['login_header', 'login_footer', 'login_enqueue_scripts'] as $hook) {
            $saved[$hook] = isset($wp_filter[$hook]) ? clone $wp_filter[$hook] : null;
            remove_all_actions($hook);
        }

        $method = new \ReflectionMethod(LoginCustomizerHandler::class, 'loadCustomizedDesign');
        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }
        $method->invoke(new LoginCustomizerHandler(), 'connection_status', 'status');

        ob_start();
        do_action('login_header');
        do_action('login_footer');
        $html = ob_get_clean();

        foreach ($saved as $hook => $copy) {
            if ($copy) {
                $wp_filter[$hook] = $copy;
            } else {
                unset($wp_filter[$hook]);
            }
        }
        delete_option('__fls_auth_customizer_settings');

        $this->assertStringContainsString('Login banner title', $html);
        $this->assertStringContainsString('fls_login_form_wrap', $html);
    }

    public function test_a_filter_that_returns_no_array_adds_nothing()
    {
        add_filter('fluent_auth/login_designer_actions', '__return_false');

        $this->assertSame([], LoginCustomizerHandler::extraActions());
    }
}
