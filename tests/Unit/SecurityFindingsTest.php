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
        delete_option('__fls_dismissed_checks');

        /*
         * The uploads check asks the web server a question. Answered here so the registry is
         * the same on every run - these tests are about how findings are assembled, and a real
         * request would make them depend on what the machine running them can reach.
         */
        add_filter('pre_http_request', function () {
            return ['response' => ['code' => 403], 'body' => 'Forbidden'];
        });
    }

    public function tearDown(): void
    {
        remove_all_filters('pre_http_request');
        Registry::reset();
        parent::tearDown();
    }

    /**
     * @param string $key
     * @param string $value
     * @return void
     */
    private function setSetting($key, $value)
    {
        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            [$key => $value]
        ));

        Helper::resetStatics();
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
            $this->assertContains(
                $finding['severity'],
                [Finding::SEVERITY_FIX, Finding::SEVERITY_LOOK, Finding::SEVERITY_ADVICE]
            );
        }
    }

    public function test_a_setting_that_is_off_is_open_and_a_setting_that_is_on_has_no_row()
    {
        $summary = Registry::summary();
        $this->assertNotEmpty($this->finding($summary, 'settings_disable_xmlrpc'));

        $this->setSetting('disable_xmlrpc', 'yes');

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
            $this->finding($summary, 'settings_integrity_scan')['severity']
        );
    }

    /**
     * The line under the title and the details panel must not be the same sentence - a row
     * that opens to show what it already said teaches people not to open rows.
     */
    public function test_a_row_never_hides_a_copy_of_what_it_already_says()
    {
        foreach (Registry::summary()['findings'] as $finding) {
            $this->assertNotContains($finding['why'], $finding['details']);
        }
    }

    /**
     * Only what the plugin recommends for every site counts, so the score stays reachable.
     *
     * Asserted as movement rather than as totals: the denominator is every scored check in the
     * registry, and pinning it to a number would mean this test failing every time the plugin
     * learns to check something new - which is not what it is here to catch.
     */
    public function test_turning_on_a_scored_recommendation_moves_the_score()
    {
        $before = Registry::summary()['score'];

        $this->setSetting('disable_xmlrpc', 'yes');
        $this->setSetting('disable_users_rest', 'yes');

        $after = Registry::summary()['score'];

        $this->assertEquals($before['done'] + 2, $after['done']);
        $this->assertEquals($before['total'], $after['total']);
    }

    /**
     * The rule the score rests on. Login alerts suit some sites and flood others - see
     * Helper::getRecommendedSettings() - so switching them on must not earn a point, or the
     * score stops meaning "this site follows the recommendations".
     */
    public function test_turning_on_an_unscored_recommendation_does_not_move_the_score()
    {
        $before = Registry::summary();

        $this->assertEquals(
            Finding::STATE_OPEN,
            $this->finding($before, 'settings_notifications')['state'],
            'Nothing was turned on, so this proves nothing'
        );

        $this->setSetting('notification_user_roles', ['administrator']);
        $this->setSetting('notification_email', '{admin_email}');

        $after = Registry::summary();

        $this->assertEmpty(
            array_filter($after['findings'], function ($finding) {
                return $finding['id'] === 'settings_notifications';
            }),
            'The recommendation was not actually satisfied'
        );

        $this->assertEquals($before['score']['done'], $after['score']['done']);
    }

    /**
     * Every button a row draws has to be backed by something.
     *
     * A finding that offers a fix or a dismissal its check never implemented reaches the
     * reader as an error message from a button they were invited to press - and the check
     * author has no way of noticing, because the row looks right. Asserted by reflection so
     * this costs nothing and mutates nothing.
     */
    public function test_no_finding_offers_a_button_its_check_cannot_honour()
    {
        /*
         * Seeded so the file checks have something to say - the contract is only worth
         * asserting over rows that exist, and an empty install produces none of theirs.
         */
        $muDir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        if (!is_dir($muDir)) {
            mkdir($muDir, 0755, true);
        }

        file_put_contents($muDir . '/fls-contract-test.php', '<?php // seeded');

        $checks = Registry::checks();
        $findings = Registry::summary()['findings'];

        unlink($muDir . '/fls-contract-test.php');

        $this->assertNotEmpty(array_filter($findings, function ($finding) {
            return $finding['group'] === 'files';
        }), 'The file checks produced nothing, so this asserted nothing about them');

        foreach ($findings as $finding) {
            $check = $checks[$finding['check']];

            if ($finding['action'] === 'fix') {
                $this->assertNotEquals(
                    Check::class,
                    (new \ReflectionMethod($check, 'fix'))->getDeclaringClass()->getName(),
                    $finding['id'] . ' offers a fix its check does not implement'
                );
            }

            if ($finding['dismiss']) {
                /*
                 * `undo` draws the way back rather than the way out, so it is unaccept() that
                 * has to be there - a row offering "count it again" over the base class's
                 * refusal is a button that errors at whoever presses it.
                 */
                $method = $finding['dismiss'] === 'undo' ? 'unaccept' : 'accept';

                $this->assertNotEquals(
                    Check::class,
                    (new \ReflectionMethod($check, $method))->getDeclaringClass()->getName(),
                    $finding['id'] . ' offers a dismissal its check does not implement'
                );
            }

            /*
             * A row that navigates has to have somewhere to send them - either one of this
             * plugin's own screens or a WordPress one. Which of the two is the check's
             * business; that there is one is not.
             */
            if ($finding['action'] === 'navigate') {
                $this->assertNotEmpty(
                    $finding['route'] ?: $finding['url'],
                    $finding['id'] . ' navigates nowhere'
                );
            }
        }
    }

    /**
     * Declining a recommendation is not the same as following it.
     *
     * It leaves the score altogether rather than counting as satisfied - both halves of the
     * fraction, not just the numerator. If dismissing handed over the point, the quickest
     * route to a hundred per cent would be to turn everything down, and the number would stop
     * meaning that the site follows the recommendations.
     */
    public function test_declining_a_recommendation_takes_it_out_of_the_score_rather_than_satisfying_it()
    {
        $before = Registry::summary()['score'];

        Registry::accept('settings', 'settings_disable_xmlrpc');

        $after = Registry::summary()['score'];

        $this->assertEquals($before['total'] - 1, $after['total']);
        $this->assertEquals($before['done'], $after['done']);

        /* And it is off the list without having been done. */
        $this->assertEmpty($this->finding(Registry::summary(), 'settings_disable_xmlrpc'));
        $this->assertNotEquals('yes', Helper::getAuthSettings()['disable_xmlrpc']);
    }

    public function test_a_declined_recommendation_stays_visible_and_can_be_taken_back()
    {
        Registry::accept('settings', 'settings_disable_xmlrpc');

        $accepted = array_column(Registry::summary()['accepted'], 'id');
        $this->assertContains('settings_disable_xmlrpc', $accepted);

        Registry::unaccept('settings', 'settings_disable_xmlrpc');

        $this->assertNotEmpty($this->finding(Registry::summary(), 'settings_disable_xmlrpc'));
    }

    /**
     * Turning something on later should earn the credit, not go on reporting that the site
     * once said no to it.
     */
    public function test_doing_a_declined_recommendation_anyway_counts_normally()
    {
        Registry::accept('settings', 'settings_disable_xmlrpc');
        $declined = Registry::summary()['score'];

        $this->setSetting('disable_xmlrpc', 'yes');

        $done = Registry::summary()['score'];

        $this->assertEquals($declined['total'] + 1, $done['total']);
        $this->assertEquals($declined['done'] + 1, $done['done']);
    }

    public function test_findings_are_ordered_worst_first()
    {
        $ranks = [Finding::SEVERITY_FIX => 0, Finding::SEVERITY_LOOK => 1, Finding::SEVERITY_ADVICE => 2];
        $previous = 0;

        foreach (Registry::summary()['findings'] as $finding) {
            $rank = $ranks[$finding['severity']];

            $this->assertGreaterThanOrEqual(
                $previous,
                $rank,
                sprintf('%s was listed after something less urgent', $finding['id'])
            );

            $previous = $rank;
        }
    }

    /**
     * Best practice is the quiet tier, and quiet has to hold everywhere the number is read.
     *
     * A site whose only open row is "you could add a line to wp-config.php" has passed every
     * check this plugin actually makes, so it must not carry a badge on the tab or a count in
     * the amber column - the tier exists precisely to stop that reading.
     */
    public function test_advice_is_listed_but_kept_out_of_what_needs_attention()
    {
        $summary = Registry::summary();
        $counts = $summary['counts'];

        $this->assertGreaterThan(0, $counts['advice'], 'No check produces advice, so this proves nothing');

        $this->assertEquals($counts['to_fix'] + $counts['look'], $counts['attention']);
        $this->assertEquals($counts['attention'] + $counts['advice'], $counts['open']);

        foreach ($summary['findings'] as $finding) {
            if ($finding['severity'] === Finding::SEVERITY_ADVICE) {
                $this->assertFalse($finding['scored'], $finding['id'] . ' is advice and should not be scored');
            }
        }
    }

    /**
     * Login alerts are a judgement about how a site is staffed, not a protection every site
     * should have on. A busy multi-author site that decided against them has not failed
     * anything, so the row must not be scored and must not read as something to fix.
     */
    public function test_login_alerts_are_offered_rather_than_counted()
    {
        $finding = $this->finding(Registry::summary(), 'settings_notifications');

        $this->assertEquals(Finding::SEVERITY_ADVICE, $finding['severity']);
        $this->assertFalse($finding['scored']);
    }

    /**
     * The roles "apply recommended" writes. Author logins on a multi-author site are a
     * mailbox filling with mail nobody reads, and that is how the alert that mattered gets
     * filtered away - so the recommendation covers the accounts that can install code.
     */
    public function test_the_recommended_alert_roles_are_the_high_privilege_ones()
    {
        $roles = Helper::getRecommendedSettings()['notification_user_roles'];

        $this->assertEquals(['administrator'], $roles);
    }

    /**
     * The one thing a site owner is most likely to mix this up with. DISALLOW_FILE_EDIT
     * removes the two editor screens; DISALLOW_FILE_MODS is what stops updates, and this
     * plugin recommends it nowhere.
     */
    public function test_the_file_editor_row_is_advice_and_never_asks_for_disallow_file_mods()
    {
        $finding = $this->finding(Registry::summary(), 'file_editor');

        $this->assertEquals(Finding::SEVERITY_ADVICE, $finding['severity']);
        $this->assertEquals('none', $finding['action']);
        $this->assertFalse($finding['scored']);

        $said = $finding['title'] . ' ' . $finding['why'] . ' ' . implode(' ', $finding['details']);

        $this->assertStringContainsString('DISALLOW_FILE_EDIT', $said);
        $this->assertStringNotContainsString('DISALLOW_FILE_MODS', $said);
    }

    /**
     * The list behind the count. "18 checks passed" asks the reader to take a number on
     * trust; this is the only place the plugin says what it actually looked at, so the count
     * and the list have to be the same thing rather than two answers to one question.
     */
    public function test_the_passed_checks_are_sent_so_the_count_can_be_opened()
    {
        $summary = Registry::summary();

        $this->assertNotEmpty($summary['passed']);
        $this->assertCount($summary['counts']['passed'], $summary['passed']);

        foreach ($summary['passed'] as $finding) {
            $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
            $this->assertNotEmpty($finding['title']);
        }

        $titles = array_column($summary['passed'], 'title');
        $sorted = $titles;
        sort($sorted, SORT_STRING);

        $this->assertEquals($sorted, $titles, 'Passed checks are listed out of order');
    }

    public function test_passing_checks_are_counted_rather_than_listed()
    {
        $before = Registry::summary();

        $this->setSetting('disable_xmlrpc', 'yes');

        $after = Registry::summary();

        /* It left the list and joined the tally, rather than doing either alone. */
        $this->assertEquals($before['counts']['passed'] + 1, $after['counts']['passed']);
        $this->assertEquals($before['counts']['open'] - 1, $after['counts']['open']);
        $this->assertEquals(count($after['findings']), $after['counts']['open']);
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
