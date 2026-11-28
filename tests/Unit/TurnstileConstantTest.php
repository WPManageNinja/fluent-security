<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\TurnstileController;
use FluentAuth\App\Services\Turnstile;

/**
 * FLUENT_AUTH_DISABLE_TURNSTILE, the way back in for an owner whose widget cannot run.
 *
 * Its own class, and its own process: a define() cannot be taken back, and the process's
 * class teardown drops the plugin's tables, which would pull them out from under any other
 * test in the same class.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class TurnstileConstantTest extends BaseTestCase
{
    public function test_the_wp_config_constant_stands_every_check_down()
    {
        update_option(Turnstile::OPTION, [
            'site_key'   => '0x-site',
            'secret_key' => '0x-secret',
            'signup'     => 'yes',
            'login'      => 'yes',
            'woo'        => 'yes'
        ]);

        $this->assertTrue(Turnstile::isActive(Turnstile::LOGIN), 'guarded before the constant');

        define('FLUENT_AUTH_DISABLE_TURNSTILE', true);

        foreach ([Turnstile::SIGNUP, Turnstile::LOGIN, Turnstile::WOO] as $place) {
            $this->assertFalse(Turnstile::isActive($place), $place);
            $this->assertTrue(Turnstile::check($place), $place . ' passes with no token');
        }

        $this->assertSame('', Turnstile::widget(Turnstile::LOGIN), 'no widget to get stuck on');
        $this->assertTrue(TurnstileController::getSettings(new \WP_REST_Request())['disabled_by_constant']);
    }
}
