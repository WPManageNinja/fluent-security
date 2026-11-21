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

    public function test_a_filter_that_returns_no_array_adds_nothing()
    {
        add_filter('fluent_auth/login_designer_actions', '__return_false');

        $this->assertSame([], LoginCustomizerHandler::extraActions());
    }
}
