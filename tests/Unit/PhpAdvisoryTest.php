<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\PhpAdvisoryHandler;

class PhpAdvisoryTest extends BaseTestCase
{
    public function tearDown(): void
    {
        wp_set_current_user(0);
        parent::tearDown();
    }

    public function test_each_maintained_branch_is_safe_from_its_fix_on()
    {
        foreach (PhpAdvisoryHandler::FIXED as $fixed) {
            $this->assertSame('safe', PhpAdvisoryHandler::statusFor($fixed));

            $parts = explode('.', $fixed);
            $parts[2] = (int)$parts[2] - 1;
            $this->assertSame('outdated', PhpAdvisoryHandler::statusFor(implode('.', $parts)));
        }
    }

    public function test_branches_without_an_official_fix_are_unsupported()
    {
        $this->assertSame('unsupported', PhpAdvisoryHandler::statusFor('8.1.34'));
        $this->assertSame('unsupported', PhpAdvisoryHandler::statusFor('7.4.33'));
    }

    public function test_branches_newer_than_the_table_are_safe()
    {
        $this->assertSame('safe', PhpAdvisoryHandler::statusFor('8.6.0'));
        $this->assertSame('safe', PhpAdvisoryHandler::statusFor('9.0.0'));
    }

    /**
     * version_compare reads "-1ubuntu" as a pre-release, which would call a patched
     * distro build outdated.
     */
    public function test_distro_suffixes_are_ignored()
    {
        $this->assertSame('safe', PhpAdvisoryHandler::statusFor('8.3.36-1ubuntu0.1'));
        $this->assertSame('outdated', PhpAdvisoryHandler::statusFor('8.3.6-0ubuntu0.24.04.5'));
    }

    public function test_notice_is_for_administrators_only()
    {
        $handler = new PhpAdvisoryHandler();
        $shown = PhpAdvisoryHandler::statusFor(PHP_VERSION) !== 'safe';

        wp_set_current_user($this->factory->user->create(['role' => 'editor']));
        $this->assertSame('', $this->render($handler));

        $admin = $this->factory->user->create(['role' => 'administrator']);
        wp_set_current_user($admin);
        $this->assertSame($shown, $this->render($handler) !== '');
    }

    private function render($handler)
    {
        ob_start();
        $handler->renderNotice();

        return trim(ob_get_clean());
    }
}
