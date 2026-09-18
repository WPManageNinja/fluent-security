<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\Checks\Plugins\TwoFaConflictCheck;
use FluentAuth\App\Services\Checks\Registry;

/**
 * The check that spots another plugin finishing our logins for us.
 *
 * What is pinned here is mostly the restraint. This one names third-party plugins in red on
 * somebody's dashboard, so every way it could be wrong about a site matters more than the
 * case it was written for: a site that runs no second factor of its own has made a choice
 * rather than a mistake, a plugin whose own switch says the feature is off is not a conflict,
 * and a plugin that merely *has* a second factor somewhere is a thing to look at rather than
 * a thing to fix.
 */
class TwoFaConflictCheckTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        delete_option(Dismissals::OPTION);
        update_option('active_plugins', []);
        Registry::reset();
    }

    public function tearDown(): void
    {
        delete_option(Dismissals::OPTION);
        delete_option('__fls_auth_settings');
        delete_option('sg_security_sg2fa');
        update_option('active_plugins', []);
        remove_all_filters('fluent_auth/2fa_conflict_plugins');
        Helper::resetStatics();
        Registry::reset();

        parent::tearDown();
    }

    private function ourTwoFaOn()
    {
        update_option('__fls_auth_settings', ['passkey_2fa' => 'yes']);
        Helper::resetStatics();
    }

    private function activate($plugins)
    {
        update_option('active_plugins', (array)$plugins);
    }

    private function findings()
    {
        $found = [];

        foreach ((new TwoFaConflictCheck())->run() as $finding) {
            $found[$finding->id()] = $finding->toArray();
        }

        return $found;
    }

    /**
     * The all-clear answers for the site, not for half of this check.
     *
     * A plugin we can only say "maybe" about leaves the confirmed list empty, and reading
     * that as "nothing found" drew a green row saying no plugin was competing directly above
     * the row naming the plugin that might be. The green one reads as the verdict, so it has
     * to stay away unless both halves came back empty.
     */
    public function test_a_maybe_withholds_the_all_clear()
    {
        $this->ourTwoFaOn();
        $this->activate(['wordfence/wordfence.php']);

        $findings = $this->findings();

        $this->assertArrayNotHasKey(TwoFaConflictCheck::FINDING_ACTIVE, $findings);
        $this->assertSame(
            Finding::STATE_OPEN,
            $findings[TwoFaConflictCheck::FINDING_POSSIBLE]['state']
        );
    }

    /* ------------------------------------------------------------ nothing to say */

    /**
     * A site running somebody else's second factor and none of ours is not misconfigured.
     * Telling it to uninstall a working plugin because we happen to be installed would be
     * this check picking a fight on behalf of a feature the owner has switched off.
     */
    public function test_a_site_not_asking_for_a_second_factor_is_left_alone()
    {
        update_option('__fls_auth_settings', ['passkey_2fa' => 'no', 'totp_2fa' => 'no', 'email2fa' => 'no']);
        Helper::resetStatics();

        $this->activate(['sg-security/sg-security.php']);
        update_option('sg_security_sg2fa', 1);

        $this->assertSame([], (new TwoFaConflictCheck())->run());
    }

    public function test_a_site_with_no_rival_installed_passes()
    {
        $this->ourTwoFaOn();

        $findings = $this->findings();

        $this->assertCount(1, $findings);
        $this->assertEquals(Finding::STATE_PASSED, $findings[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
    }

    /**
     * The plugin is there and its own switch says the second factor is off. Nothing is
     * wrong, and a row saying otherwise would be the check reporting an installation
     * rather than a conflict.
     */
    public function test_a_rival_with_its_second_factor_switched_off_is_not_a_conflict()
    {
        $this->ourTwoFaOn();
        $this->activate(['sg-security/sg-security.php']);
        update_option('sg_security_sg2fa', 0);

        $findings = $this->findings();

        $this->assertCount(1, $findings);
        $this->assertEquals(Finding::STATE_PASSED, $findings[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
    }

    /* ------------------------------------------------------------ the real thing */

    public function test_siteground_security_with_two_factor_on_is_reported_to_fix()
    {
        $this->ourTwoFaOn();
        $this->activate(['sg-security/sg-security.php']);
        update_option('sg_security_sg2fa', 1);

        $finding = $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE];

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('SiteGround', $finding['title']);
        $this->assertStringContainsString('login-settings', $finding['url']);
        $this->assertStringContainsString('Login Security', implode(' ', $finding['details']));
    }

    /**
     * A plugin that exists only to provide a second factor needs no toggle read: being
     * active is the whole answer.
     */
    public function test_a_two_factor_only_plugin_needs_no_option_to_count()
    {
        $this->ourTwoFaOn();
        $this->activate(['wp-2fa/wp-2fa.php']);

        $finding = $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE];

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('WP 2FA', $finding['title']);
    }

    /**
     * Two at once is still one decision, so it is still one row - and the button stops
     * offering to open "its" settings, because there is no single "it" to open.
     */
    public function test_several_rivals_are_one_finding_pointing_at_the_plugins_screen()
    {
        $this->ourTwoFaOn();
        $this->activate(['wp-2fa/wp-2fa.php', 'rublon/rublon2factor.php']);

        $finding = $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE];

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('plugins.php', $finding['url']);
        $this->assertCount(4, $finding['details']);
    }

    /* ------------------------------------------------------- the ones we can't read */

    /**
     * Wordfence keeps its settings in its own tables, so all we can honestly say is that
     * it has the feature. That is a different sentence from the one above and gets a
     * different severity.
     */
    public function test_a_plugin_whose_switch_we_cannot_read_is_only_worth_a_look()
    {
        $this->ourTwoFaOn();
        $this->activate(['wordfence/wordfence.php']);

        $findings = $this->findings();

        $possible = $findings[TwoFaConflictCheck::FINDING_POSSIBLE];
        $this->assertEquals(Finding::SEVERITY_LOOK, $possible['severity']);
        $this->assertStringContainsString('Wordfence', $possible['title']);
    }

    /**
     * No passed twin for the maybe. "Nothing might be wrong" is not a reassurance, and a
     * green row saying it would be noise on every site that has none of these installed.
     */
    public function test_the_maybe_says_nothing_when_there_is_no_maybe()
    {
        $this->ourTwoFaOn();

        $this->assertArrayNotHasKey(TwoFaConflictCheck::FINDING_POSSIBLE, $this->findings());
    }

    /* --------------------------------------------- how a plugin is found and asked */

    /**
     * Declare one rival, so a test says what it means without depending on which real
     * plugins happen to carry an `enabled` answer.
     */
    private function rival($extra = [])
    {
        add_filter('fluent_auth/2fa_conflict_plugins', function () use ($extra) {
            return [array_merge([
                'plugin' => 'made-up/made-up.php',
                'name'   => 'Made Up Security',
                'where'  => 'Somewhere',
                'url'    => 'admin.php?page=made-up'
            ], $extra)];
        });
    }

    /**
     * A constant is better evidence than a path. The entry in `active_plugins` names a
     * folder, so renaming it - or installing the same plugin as an mu-plugin - hides a
     * plugin that is still there and still hooking `wp_login`.
     */
    public function test_a_plugin_is_found_by_its_constant_with_no_entry_in_active_plugins()
    {
        define('FLS_TEST_RIVAL_CONSTANT', '1.0');

        $this->ourTwoFaOn();
        $this->rival(['constants' => ['FLS_TEST_RIVAL_CONSTANT']]);

        $finding = $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE];

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertStringContainsString('Made Up Security', $finding['title']);
    }

    public function test_a_plugin_is_found_by_a_loaded_class()
    {
        $this->ourTwoFaOn();
        $this->rival(['classes' => [self::class]]);

        $this->assertArrayHasKey(TwoFaConflictCheck::FINDING_ACTIVE, $this->findings());
    }

    /**
     * The path is still consulted, so a constant we have guessed wrong costs the accuracy of
     * one entry rather than losing the plugin entirely.
     */
    public function test_a_wrong_constant_falls_back_to_the_plugin_path()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['constants' => ['FLS_A_CONSTANT_NOBODY_DEFINES']]);

        $this->assertArrayHasKey(TwoFaConflictCheck::FINDING_ACTIVE, $this->findings());
    }

    public function test_a_plugin_that_says_its_second_factor_is_off_is_dropped()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () { return false; }]);

        $findings = $this->findings();

        $this->assertCount(1, $findings);
        $this->assertEquals(Finding::STATE_PASSED, $findings[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
    }

    public function test_a_plugin_that_says_its_second_factor_is_on_is_a_conflict_to_fix()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () { return true; }]);

        $this->assertEquals(
            Finding::SEVERITY_FIX,
            $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE]['severity']
        );
    }

    /**
     * "It will not say" is a third answer and has to stay one. Reading it as off drops a
     * real conflict silently; reading it as on accuses a site of something unproven.
     */
    public function test_a_plugin_that_will_not_say_is_only_worth_a_look()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () { return null; }]);

        $findings = $this->findings();

        $this->assertArrayNotHasKey(TwoFaConflictCheck::FINDING_ACTIVE, $findings);
        $this->assertEquals(Finding::SEVERITY_LOOK, $findings[TwoFaConflictCheck::FINDING_POSSIBLE]['severity']);
    }

    /**
     * Their code runs inside our request. A getter that fatals on a version whose signature
     * we guessed wrong would otherwise take the whole security screen with it, over a
     * question that was only deciding how loudly to word one row.
     */
    public function test_a_plugin_whose_own_code_blows_up_is_only_worth_a_look()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () {
            /* An Error, not an Exception - which is what a bad call actually raises. */
            return \NoSuchClassAnywhere::answer();
        }]);

        $findings = $this->findings();

        $this->assertArrayNotHasKey(TwoFaConflictCheck::FINDING_ACTIVE, $findings);
        $this->assertEquals(Finding::SEVERITY_LOOK, $findings[TwoFaConflictCheck::FINDING_POSSIBLE]['severity']);
    }

    /**
     * An option that is not there is the shape a wrong option name takes. Reading it as
     * "switched off" is the one failure that loses a real conflict instead of softening it,
     * so absent has to answer "look" rather than "nothing here".
     */
    public function test_a_missing_option_is_a_look_rather_than_an_all_clear()
    {
        $this->ourTwoFaOn();
        $this->activate(['sg-security/sg-security.php']);
        delete_option('sg_security_sg2fa');

        $findings = $this->findings();

        $this->assertArrayNotHasKey(TwoFaConflictCheck::FINDING_ACTIVE, $findings);
        $this->assertStringContainsString(
            'SiteGround',
            $findings[TwoFaConflictCheck::FINDING_POSSIBLE]['title']
        );
    }

    /**
     * All-In-One Security bundles the same Simba two-factor library that the standalone
     * "Two Factor Authentication" plugin is built from, and defines
     * Simba_Two_Factor_Authentication_1 exactly as that plugin does. Matching the standalone
     * on that class would report a plugin the site has not got, by name, in red - so the
     * entry matches `..._Plugin`, which only the standalone defines.
     *
     * Verified against both plugins' source: AIOS declares `_1` and
     * `AIO_WP_Security_Simba_Two_Factor_Authentication_Plugin`, never plain `..._Plugin`.
     */
    public function test_the_shared_simba_library_is_not_mistaken_for_the_standalone_plugin()
    {
        $this->ourTwoFaOn();

        /* What AIOS loading its bundled copy looks like from here. */
        if (!class_exists('Simba_Two_Factor_Authentication_1', false)) {
            class_alias(self::class, 'Simba_Two_Factor_Authentication_1');
        }

        $findings = $this->findings();

        $this->assertCount(1, $findings);
        $this->assertEquals(Finding::STATE_PASSED, $findings[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
    }

    /* ------------------------------------------------------------------ dismissal */

    /**
     * A site that has genuinely made the two coexist - disjoint roles, a filter - must be
     * able to put the row down, and separately for each of the two findings.
     */
    public function test_each_finding_can_be_accepted_on_its_own()
    {
        $this->ourTwoFaOn();
        $this->activate(['wp-2fa/wp-2fa.php', 'wordfence/wordfence.php']);

        $check = new TwoFaConflictCheck();
        $check->accept(TwoFaConflictCheck::FINDING_ACTIVE);

        $findings = $this->findings();

        $this->assertEquals(Finding::STATE_ACCEPTED, $findings[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
        $this->assertEquals(Finding::STATE_OPEN, $findings[TwoFaConflictCheck::FINDING_POSSIBLE]['state']);

        $check->unaccept(TwoFaConflictCheck::FINDING_ACTIVE);

        $this->assertEquals(Finding::STATE_OPEN, $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
    }

    public function test_an_unknown_finding_id_is_refused_rather_than_silently_dismissed()
    {
        $this->assertWPError((new TwoFaConflictCheck())->accept('something_else'));
        $this->assertWPError((new TwoFaConflictCheck())->unaccept('something_else'));
        $this->assertSame([], Dismissals::all());
    }

    /* -------------------------------------------------------------------- the list */

    /**
     * The way out for a site running something we have never heard of, and the way back
     * for a site whose pairing genuinely works.
     */
    public function test_the_list_of_rivals_can_be_filtered()
    {
        $this->ourTwoFaOn();
        $this->activate(['some-plugin/some-plugin.php']);

        add_filter('fluent_auth/2fa_conflict_plugins', function () {
            return [[
                'plugin'  => 'some-plugin/some-plugin.php',
                'name'    => 'Some Plugin',
                'where'   => 'Somewhere',
                'certain' => true
            ]];
        });

        $finding = $this->findings()[TwoFaConflictCheck::FINDING_ACTIVE];

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('Some Plugin', $finding['title']);
        // No url of its own, so the button falls back to the plugins screen.
        $this->assertStringContainsString('plugins.php', $finding['url']);
    }

    /**
     * Anything at all can arrive through the filter, and what it feeds is the title of a
     * red row. A malformed entry is dropped rather than rendered half-empty.
     */
    public function test_a_malformed_filtered_entry_is_dropped()
    {
        $this->ourTwoFaOn();
        $this->activate(['some-plugin/some-plugin.php']);

        add_filter('fluent_auth/2fa_conflict_plugins', function () {
            return [
                'not an array',
                ['plugin' => 'some-plugin/some-plugin.php'],
                ['name' => 'No plugin file']
            ];
        });

        $findings = $this->findings();

        $this->assertCount(1, $findings);
        $this->assertEquals(Finding::STATE_PASSED, $findings[TwoFaConflictCheck::FINDING_ACTIVE]['state']);
    }

    public function test_the_check_is_registered()
    {
        $this->assertArrayHasKey('two_fa_conflict', Registry::checks());
    }
}
