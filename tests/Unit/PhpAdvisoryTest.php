<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Hooks\Handlers\PhpAdvisoryHandler;

class PhpAdvisoryTest extends BaseTestCase
{
    public function tearDown(): void
    {
        wp_set_current_user(0);
        delete_option(PhpAdvisoryHandler::DISMISSED_OPTION);
        remove_all_filters('wp_redirect');
        unset($_REQUEST['_wpnonce'], $_GET['_wpnonce']);
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
        $admin = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($admin);

        $advisory = PhpAdvisoryHandler::advisory();
        $status = PhpAdvisoryHandler::statusFor(PHP_VERSION);

        if ($status === 'safe') {
            $this->assertNull($advisory);
        } else {
            $this->assertStringContainsString(PhpAdvisoryHandler::shortVersion(PHP_VERSION), $advisory['title']);
            $this->assertNotEmpty($advisory['body']);
            $this->assertSame(PhpAdvisoryHandler::LEARN_MORE_URL, $advisory['learn_more_url']);
        }

        $protection = \FluentAuth\App\Http\Controllers\DashboardController::getDashboard(new \WP_REST_Request('GET', '/fluent-auth/dashboard'))['protection'];

        $this->assertSame($advisory, $protection['php_advisory']);
    }

    /**
     * Ubuntu 24.04 ships the fix as 8.3.6-0ubuntu0.24.04.13, so the version alone cannot
     * say the server is exposed.
     */
    public function test_an_outdated_version_is_a_maybe_and_names_the_fix()
    {
        $advisory = PhpAdvisoryHandler::advisory('8.3.6-0ubuntu0.24.04.13');

        $this->assertSame('outdated', $advisory['status']);
        $this->assertStringContainsString('8.3.6, which may have', $advisory['title']);
        $this->assertStringContainsString('without changing the version number', $advisory['body']);
        $this->assertStringContainsString('8.3.36', $advisory['body']);
    }

    public function test_an_unsupported_version_keeps_its_wording()
    {
        $advisory = PhpAdvisoryHandler::advisory('7.4.33');

        $this->assertSame('unsupported', $advisory['status']);
        $this->assertStringContainsString('7.4.33, which has a critical', $advisory['title']);
        $this->assertStringContainsString('no longer gets security fixes', $advisory['body']);
    }

    public function test_a_dismissal_holds_for_that_exact_version_only()
    {
        $this->assertNotNull(PhpAdvisoryHandler::advisory('8.3.6-0ubuntu0.24.04.13'));

        PhpAdvisoryHandler::dismiss('8.3.6-0ubuntu0.24.04.13');

        $this->assertNull(PhpAdvisoryHandler::advisory('8.3.6-0ubuntu0.24.04.13'));
        $this->assertNotNull(PhpAdvisoryHandler::advisory('8.3.6-0ubuntu0.24.04.14'));
        $this->assertNotNull(PhpAdvisoryHandler::advisory('8.3.7'));
        $this->assertSame('outdated', PhpAdvisoryHandler::statusFor('8.3.6-0ubuntu0.24.04.13'));
    }

    public function test_a_dismissal_hides_the_notice_and_the_dashboard_block()
    {
        if (PhpAdvisoryHandler::statusFor(PHP_VERSION) === 'safe') {
            $this->markTestSkipped('This PHP has no advisory to dismiss.');
        }

        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));
        PhpAdvisoryHandler::dismiss();

        $this->assertSame('', $this->render(new PhpAdvisoryHandler()));
        $protection = \FluentAuth\App\Http\Controllers\DashboardController::getDashboard(new \WP_REST_Request('GET', '/fluent-auth/dashboard'))['protection'];
        $this->assertNull($protection['php_advisory']);
    }

    public function test_only_administrators_get_a_dismiss_link()
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'editor']));
        $this->assertSame('', PhpAdvisoryHandler::advisory('8.3.6')['dismiss_url']);

        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));
        $url = PhpAdvisoryHandler::advisory('8.3.6')['dismiss_url'];

        $this->assertStringContainsString('admin-post.php?action=' . PhpAdvisoryHandler::DISMISS_ACTION, $url);
        $this->assertStringNotContainsString('&amp;', $url);
        $this->assertStringContainsString('_wpnonce=' . wp_create_nonce(PhpAdvisoryHandler::DISMISS_ACTION), $url);
    }

    public function test_dismissing_needs_the_capability()
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'editor']));
        $_REQUEST['_wpnonce'] = wp_create_nonce(PhpAdvisoryHandler::DISMISS_ACTION);

        $this->expectException(\WPDieException::class);

        try {
            (new PhpAdvisoryHandler())->handleDismiss();
        } finally {
            $this->assertFalse(get_option(PhpAdvisoryHandler::DISMISSED_OPTION));
        }
    }

    public function test_dismissing_needs_the_nonce()
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));
        $_REQUEST['_wpnonce'] = 'forged';

        $this->expectException(\WPDieException::class);

        try {
            (new PhpAdvisoryHandler())->handleDismiss();
        } finally {
            $this->assertFalse(get_option(PhpAdvisoryHandler::DISMISSED_OPTION));
        }
    }

    public function test_an_administrator_dismisses_the_running_version()
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));
        $_REQUEST['_wpnonce'] = wp_create_nonce(PhpAdvisoryHandler::DISMISS_ACTION);

        add_filter('wp_redirect', function () {
            throw new \RuntimeException('redirected');
        });

        try {
            (new PhpAdvisoryHandler())->handleDismiss();
            $this->fail('Expected a redirect.');
        } catch (\RuntimeException $e) {
            $this->assertSame('redirected', $e->getMessage());
        }

        $this->assertSame(PHP_VERSION, get_option(PhpAdvisoryHandler::DISMISSED_OPTION));
        $this->assertTrue(PhpAdvisoryHandler::isDismissed());
    }

    public function test_a_sury_build_below_the_fix_is_confirmed_and_cannot_be_dismissed()
    {
        $sury = '8.4.20-1+ubuntu22.04.1+deb.sury.org+1';
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));

        PhpAdvisoryHandler::dismiss($sury);
        $advisory = PhpAdvisoryHandler::advisory($sury);

        $this->assertTrue($advisory['confirmed']);
        $this->assertStringContainsString('8.4.20, which has a critical', $advisory['title']);
        $this->assertStringContainsString('update PHP to 8.4.27', $advisory['body']);
        $this->assertSame('', $advisory['dismiss_url']);
    }

    public function test_only_sury_builds_are_confirmed()
    {
        $this->assertNull(PhpAdvisoryHandler::advisory('8.4.27-1+ubuntu22.04.1+deb.sury.org+1'));
        $this->assertFalse(PhpAdvisoryHandler::advisory('8.3.6-0ubuntu0.24.04.13')['confirmed']);
        $this->assertFalse(PhpAdvisoryHandler::advisory('8.3.6')['confirmed']);
        $this->assertFalse(PhpAdvisoryHandler::advisory('8.0.30')['confirmed']);
        $this->assertFalse(PhpAdvisoryHandler::advisory('8.1.2-1+ubuntu22.04.1+deb.sury.org+1')['confirmed']);
    }
}
