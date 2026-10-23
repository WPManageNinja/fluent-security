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
        $this->assertSame('safe', PhpAdvisoryHandler::statusFor('8.2.35-1+0~20261021.60+debian12~1.gbp4f2c1a'));
        $this->assertSame('outdated', PhpAdvisoryHandler::statusFor('8.4.20-1+ubuntu22.04.1+deb.sury.org+1'));
        $this->assertSame('unsupported', PhpAdvisoryHandler::statusFor('7.4.33-nmm7'));
    }

    public function test_the_notice_shows_only_the_leading_version()
    {
        $this->assertSame('8.1.2', PhpAdvisoryHandler::shortVersion('8.1.2-1ubuntu2.20'));
        $this->assertSame('8.2.35', PhpAdvisoryHandler::shortVersion('8.2.35-1+0~20261021.60+debian12~1.gbp4f2c1a'));
        $this->assertSame('8.4.27', PhpAdvisoryHandler::shortVersion('8.4.27'));
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

    /**
     * The dashboard hides WordPress notices, so it reads the same advisory to show it in
     * its own sidebar.
     */
    public function test_the_dashboard_gets_the_same_advisory_as_the_notice()
    {
        $advisory = PhpAdvisoryHandler::advisory();
        $status = PhpAdvisoryHandler::statusFor(PHP_VERSION);

        if ($status === 'safe') {
            $this->assertNull($advisory);
        } else {
            $this->assertStringContainsString(PhpAdvisoryHandler::shortVersion(PHP_VERSION), $advisory['title']);
            $this->assertNotEmpty($advisory['body']);
            $this->assertSame(PhpAdvisoryHandler::LEARN_MORE_URL, $advisory['learn_more_url']);
        }

        $admin = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($admin);

        $protection = \FluentAuth\App\Http\Controllers\DashboardController::getDashboard(new \WP_REST_Request('GET', '/fluent-auth/dashboard'))['protection'];

        $this->assertSame($advisory, $protection['php_advisory']);
    }
}
