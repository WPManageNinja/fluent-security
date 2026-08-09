<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Checks\Check;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Checks\Registry;

/**
 * The registry, and the settings adapter that is currently its only member.
 *
 * The point of these is the contract rather than any one check: the screen renders whatever
 * comes back from summary() without knowing what produced it, so the shape of that answer is
 * the thing that must not drift.
 */
class SecurityFindingsTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        update_option('__fls_auth_settings', [
            'disable_xmlrpc'          => 'no',
            'disable_app_login'       => 'no',
            'disable_users_rest'      => 'no',
            'secure_signup_form'      => 'no',
            'notification_user_roles' => [],
            'notification_email'      => '{admin_email}',
            'totp_2fa'                => 'no',
            'email2fa'                => 'no'
        ]);

        Helper::resetStatics();
        Registry::reset();
        delete_option('__fls_integrity_settings');
    }

    public function tearDown(): void
    {
        Registry::reset();
        parent::tearDown();
    }

    /**
     * @param array $summary
     * @param string $id
     * @return array
     */
    private function finding($summary, $id)
    {
        foreach ($summary['findings'] as $finding) {
            if ($finding['id'] === $id) {
                return $finding;
            }
        }

        return [];
    }

    public function test_every_setting_recommendation_becomes_a_finding()
    {
        $summary = Registry::summary();

        $this->assertNotEmpty($summary['findings']);

        foreach ($summary['findings'] as $finding) {
            $this->assertNotEmpty($finding['id']);
            $this->assertNotEmpty($finding['check']);
            $this->assertNotEmpty($finding['title']);
            $this->assertContains($finding['severity'], [Finding::SEVERITY_FIX, Finding::SEVERITY_LOOK]);
        }
    }

    public function test_a_setting_that_is_off_is_open_and_a_setting_that_is_on_has_no_row()
    {
        $summary = Registry::summary();
        $this->assertNotEmpty($this->finding($summary, 'settings_disable_xmlrpc'));

        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['disable_xmlrpc' => 'yes']
        ));
        Helper::resetStatics();

        $summary = Registry::summary();
        $this->assertEmpty($this->finding($summary, 'settings_disable_xmlrpc'));
    }

    /**
     * The two severities have to mean something, and what they mean is whether this is a
     * recommendation for every site. Application passwords deliberately are not - see
     * Helper::getRecommendedSettings() - so that row must never read as a failing.
     */
    public function test_only_a_scored_recommendation_reads_as_something_to_fix()
    {
        $summary = Registry::summary();

        $this->assertEquals(
            Finding::SEVERITY_FIX,
            $this->finding($summary, 'settings_disable_xmlrpc')['severity']
        );

        $this->assertEquals(
            Finding::SEVERITY_LOOK,
            $this->finding($summary, 'settings_disable_app_login')['severity']
        );
    }

    public function test_a_check_in_use_is_reported_as_a_fact_with_no_button()
    {
        $user = $this->factory->user->create(['role' => 'administrator']);
        \WP_Application_Passwords::create_new_application_password($user, ['name' => 'Test integration']);

        $summary = Registry::summary();
        $finding = $this->finding($summary, 'settings_disable_app_login');

        $this->assertEquals(Finding::SEVERITY_LOOK, $finding['severity']);
        $this->assertEquals('navigate', $finding['action']);
        $this->assertStringContainsString('In use', $finding['why']);

        /*
         * "Set up" would say there is work outstanding here, and there is not - something on
         * this site relies on the setting being off. All that can honestly be offered is a
         * look at what that something is.
         */
        $this->assertEquals('Review', $finding['label']);
    }

    /**
     * The line under the title and the details panel must not be the same sentence - a row
     * that opens to show what it already said teaches people not to open rows.
     */
    public function test_a_row_never_hides_a_copy_of_what_it_already_says()
    {
        $user = $this->factory->user->create(['role' => 'administrator']);
        \WP_Application_Passwords::create_new_application_password($user, ['name' => 'Test integration']);

        foreach (Registry::summary()['findings'] as $finding) {
            $this->assertNotContains($finding['why'], $finding['details']);
        }
    }

    /**
     * Only what the plugin recommends for every site counts, so the score stays reachable.
     */
    public function test_the_score_counts_scored_recommendations_only()
    {
        $summary = Registry::summary();

        $this->assertEquals(0, $summary['score']['done']);
        $this->assertEquals(5, $summary['score']['total']);
        $this->assertEquals(0, $summary['score']['percent']);

        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['disable_xmlrpc' => 'yes', 'disable_users_rest' => 'yes']
        ));
        Helper::resetStatics();

        $summary = Registry::summary();

        $this->assertEquals(2, $summary['score']['done']);
        $this->assertEquals(5, $summary['score']['total']);
        $this->assertEquals(40, $summary['score']['percent']);
    }

    public function test_findings_are_ordered_worst_first()
    {
        $seenLook = false;

        foreach (Registry::summary()['findings'] as $finding) {
            if ($finding['severity'] === Finding::SEVERITY_LOOK) {
                $seenLook = true;
                continue;
            }

            $this->assertFalse($seenLook, 'A fix-this finding was listed after a worth-a-look one');
        }
    }

    public function test_passing_checks_are_counted_rather_than_listed()
    {
        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['disable_xmlrpc' => 'yes']
        ));
        Helper::resetStatics();

        $summary = Registry::summary();

        $this->assertEquals(1, $summary['counts']['passed']);
        $this->assertEquals(count($summary['findings']), $summary['counts']['open']);
    }

    public function test_a_fix_turns_the_setting_on()
    {
        $result = Registry::fix('settings', 'settings_disable_xmlrpc');

        $this->assertFalse(is_wp_error($result));
        $this->assertEquals('yes', Helper::getAuthSettings()['disable_xmlrpc']);
    }

    /**
     * The endpoint names a finding, never a setting, so an unknown one is refused rather
     * than written.
     */
    public function test_an_unknown_finding_is_refused()
    {
        $this->assertWpErrorWithCode(Registry::fix('settings', 'settings_not_a_thing'), 'unknown_check');
        $this->assertWpErrorWithCode(Registry::fix('not_a_check', 'settings_disable_xmlrpc'), 'unknown_check');
    }

    public function test_fixing_something_already_on_is_refused()
    {
        Registry::fix('settings', 'settings_disable_xmlrpc');

        $this->assertWpErrorWithCode(
            Registry::fix('settings', 'settings_disable_xmlrpc'),
            'already_done'
        );
    }

    /**
     * A check that throws must cost the reader that check's answer and no more.
     */
    public function test_one_broken_check_does_not_take_the_others_with_it()
    {
        add_filter('fluent_auth/security_checks', function ($checks) {
            $checks[] = new BrokenTestCheck();

            return $checks;
        });

        Registry::reset();

        $summary = Registry::summary();

        $this->assertNotEmpty($summary['findings']);
        $this->assertEmpty($this->finding($summary, 'broken_thing'));

        remove_all_filters('fluent_auth/security_checks');
        Registry::reset();
    }

    public function test_deep_checks_are_left_out_of_a_page_load()
    {
        add_filter('fluent_auth/security_checks', function ($checks) {
            $checks[] = new DeepTestCheck();

            return $checks;
        });

        Registry::reset();

        $this->assertEmpty($this->finding(Registry::summary(), 'deep_thing'));
        $this->assertNotEmpty($this->finding(Registry::summary([Check::COST_DEEP]), 'deep_thing'));

        remove_all_filters('fluent_auth/security_checks');
        Registry::reset();
    }
}

class BrokenTestCheck extends Check
{
    public function id()
    {
        return 'broken';
    }

    public function group()
    {
        return 'files';
    }

    public function run()
    {
        throw new \Exception('This check cannot run here');
    }
}

class DeepTestCheck extends Check
{
    public function id()
    {
        return 'deep';
    }

    public function group()
    {
        return 'files';
    }

    public function cost()
    {
        return self::COST_DEEP;
    }

    public function run()
    {
        return [
            new Finding([
                'id'    => 'deep_thing',
                'check' => 'deep',
                'group' => 'files',
                'title' => 'Something that took a while to find'
            ])
        ];
    }
}
