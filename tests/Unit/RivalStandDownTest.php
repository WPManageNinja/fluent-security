<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\RivalStandDown;

/**
 * Asking the other second factor to stand aside for one request.
 *
 * What is pinned here is the scoping rather than the asking. Standing a rival down is this
 * plugin switching off somebody else's security control, and it is only defensible because
 * it lasts for one call - the wp_signon() completing a challenge the user has already
 * answered. A stand-down that outlived that call, or one that took a site's own filters with
 * it on the way out, would be a security regression this plugin caused.
 */
class RivalStandDownTest extends BaseTestCase
{
    public function tearDown(): void
    {
        RivalStandDown::resume();
        remove_all_filters('fluent_auth/stand_down_rival_2fa');
        remove_all_filters('fluent_auth/2fa_stand_down_handlers');

        foreach (RivalStandDown::handlers() as $handler) {
            remove_all_filters($handler['filter']);
        }

        parent::tearDown();
    }

    private function ask($filter, $default)
    {
        return apply_filters($filter, $default, 1);
    }

    public function test_each_rival_is_asked_to_stand_down()
    {
        RivalStandDown::standDown();

        /* Empty providers: the same state a user with no second factor configured is in. */
        $this->assertSame([], $this->ask('two_factor_enabled_providers_for_user', ['totp']));
        $this->assertFalse($this->ask('wp_defender_2fa_user_enabled', true));
        $this->assertFalse($this->ask('itsec_two_factor_interstitial_show_to_user', true));
    }

    /**
     * The whole safety argument. Outside the one call, every rival must behave exactly as
     * though this plugin were not installed.
     */
    public function test_nothing_is_stood_down_before_or_after_the_window()
    {
        $this->assertTrue($this->ask('wp_defender_2fa_user_enabled', true));

        RivalStandDown::standDown();
        RivalStandDown::resume();

        $this->assertTrue($this->ask('wp_defender_2fa_user_enabled', true));
        $this->assertSame(['totp'], $this->ask('two_factor_enabled_providers_for_user', ['totp']));
        $this->assertTrue($this->ask('itsec_two_factor_interstitial_show_to_user', true));
    }

    public function test_every_filter_is_detached_on_resume()
    {
        RivalStandDown::standDown();
        RivalStandDown::resume();

        foreach (RivalStandDown::handlers() as $handler) {
            $this->assertFalse(
                has_filter($handler['filter']),
                $handler['filter'] . ' was left attached'
            );
        }
    }

    /**
     * A site's own callback on the same hook has to survive. These filters exist so a site
     * can make this decision for itself, and resuming by filter name rather than by the
     * callback we added would throw that away as a side effect of one login.
     */
    public function test_a_sites_own_filter_on_the_same_hook_survives()
    {
        $theirs = function () {
            return 'theirs';
        };

        add_filter('wp_defender_2fa_user_enabled', $theirs);

        RivalStandDown::standDown();
        RivalStandDown::resume();

        $this->assertTrue(has_filter('wp_defender_2fa_user_enabled', $theirs) !== false);
        $this->assertSame('theirs', $this->ask('wp_defender_2fa_user_enabled', true));

        remove_filter('wp_defender_2fa_user_enabled', $theirs);
    }

    /**
     * Ours has to be the last word while it is attached, or the rival acts on somebody
     * else's answer and the login fails anyway.
     */
    public function test_the_stand_down_outranks_a_filter_already_on_the_hook()
    {
        add_filter('wp_defender_2fa_user_enabled', function () {
            return true;
        }, 99);

        RivalStandDown::standDown();

        $this->assertFalse($this->ask('wp_defender_2fa_user_enabled', true));
    }

    public function test_a_site_can_refuse_to_stand_rivals_down()
    {
        add_filter('fluent_auth/stand_down_rival_2fa', '__return_false');

        RivalStandDown::standDown();

        $this->assertTrue($this->ask('wp_defender_2fa_user_enabled', true));
        $this->assertSame([], RivalStandDown::handledRivals());
    }

    /**
     * Calling it twice must not attach a second copy - the second resume() would otherwise
     * have nothing recorded to remove and would leave the first set hooked.
     */
    public function test_standing_down_twice_attaches_one_set()
    {
        RivalStandDown::standDown();
        RivalStandDown::standDown();
        RivalStandDown::resume();

        $this->assertFalse(has_filter('wp_defender_2fa_user_enabled'));
    }

    /**
     * A malformed entry - from the filter that lets a site add one - must be skipped rather
     * than attached as a filter with no value to return.
     */
    public function test_a_malformed_handler_is_ignored()
    {
        add_filter('fluent_auth/2fa_stand_down_handlers', function () {
            return [
                'broken' => ['rival' => 'x/x.php'],
                'fine'   => ['rival' => 'y/y.php', 'filter' => 'fls_test_stand_down', 'value' => false]
            ];
        });

        RivalStandDown::standDown();

        $this->assertFalse($this->ask('fls_test_stand_down', true));

        RivalStandDown::resume();

        $this->assertTrue($this->ask('fls_test_stand_down', true));
    }

    public function test_handled_rivals_are_reported_for_the_conflict_check()
    {
        $handled = RivalStandDown::handledRivals();

        $this->assertContains('defender-security/wp-defender.php', $handled);
        $this->assertContains('better-wp-security/better-wp-security.php', $handled);
        $this->assertContains('two-factor/two-factor.php', $handled);

        /* No hook exists for these, so the check must go on reporting them as a fix. */
        $this->assertNotContains('wordfence/wordfence.php', $handled);
        $this->assertNotContains('sg-security/sg-security.php', $handled);
    }
}
