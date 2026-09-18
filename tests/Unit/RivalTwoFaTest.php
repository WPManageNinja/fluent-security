<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\TwoFa\RivalTwoFa;

/**
 * Finding another plugin that also wants to finish the login.
 *
 * What is pinned here is mostly the restraint. This names a third-party plugin in a warning
 * box on somebody's settings screen, so every way it could be wrong about a site matters more
 * than the case it was written for: a site running no second factor of its own has made a
 * choice rather than a mistake, a plugin whose own switch says the feature is off is not a
 * conflict, and a plugin that merely *might* have one somewhere is not worth a warning at all.
 */
class RivalTwoFaTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        update_option('active_plugins', []);
    }

    public function tearDown(): void
    {
        delete_option('__fls_auth_settings');
        delete_option('sg_security_sg2fa');
        update_option('active_plugins', []);
        remove_all_filters('fluent_auth/2fa_conflict_plugins');
        Helper::resetStatics();

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

    /* ------------------------------------------------------------ nothing to say */

    /**
     * A site running somebody else's second factor and none of ours is not misconfigured.
     * Warning it about a conflict would be picking a fight on behalf of a feature its owner
     * has switched off.
     */
    public function test_a_site_not_asking_for_a_second_factor_is_left_alone()
    {
        update_option('__fls_auth_settings', ['passkey_2fa' => 'no', 'totp_2fa' => 'no', 'email2fa' => 'no']);
        Helper::resetStatics();

        $this->activate(['sg-security/sg-security.php']);
        update_option('sg_security_sg2fa', 1);

        $this->assertNull(RivalTwoFa::notice());
    }

    public function test_a_site_with_no_rival_installed_says_nothing()
    {
        $this->ourTwoFaOn();

        $this->assertNull(RivalTwoFa::notice());
    }

    /**
     * The plugin is there and its own switch says the second factor is off. Nothing is wrong,
     * and a warning would be reporting an installation rather than a conflict.
     */
    public function test_a_rival_with_its_second_factor_switched_off_says_nothing()
    {
        $this->ourTwoFaOn();
        $this->activate(['sg-security/sg-security.php']);
        update_option('sg_security_sg2fa', 0);

        $this->assertNull(RivalTwoFa::notice());
    }

    /**
     * A maybe is not worth a warning box. Saying it here would put a red panel in front of
     * every site that merely has Wordfence installed, and a warning that is usually wrong
     * stops being read.
     */
    public function test_a_plugin_we_cannot_read_is_not_worth_a_warning()
    {
        $this->ourTwoFaOn();
        $this->activate(['wordfence/wordfence.php']);

        $this->assertNull(RivalTwoFa::notice());
    }

    /* ------------------------------------------------------------ the real thing */

    public function test_siteground_with_two_factor_on_is_reported()
    {
        $this->ourTwoFaOn();
        $this->activate(['sg-security/sg-security.php']);
        update_option('sg_security_sg2fa', 1);

        $notice = RivalTwoFa::notice();

        $this->assertNotNull($notice);
        $this->assertSame(['Security Optimizer by SiteGround'], $notice['names']);
        $this->assertStringContainsString('Login Security', implode(' ', $notice['where']));
        $this->assertStringContainsString('login-settings', $notice['url']);
    }

    /**
     * A plugin that exists only to provide a second factor needs no toggle read: being there
     * is the whole answer.
     */
    public function test_a_two_factor_only_plugin_needs_no_option_to_count()
    {
        $this->ourTwoFaOn();
        $this->activate(['wp-2fa/wp-2fa.php']);

        $notice = RivalTwoFa::notice();

        $this->assertNotNull($notice);
        $this->assertSame(['WP 2FA by Melapress'], $notice['names']);
    }

    /**
     * Two at once is still one box, and the link stops offering to open "its" settings
     * because there is no single "it" to open.
     */
    public function test_several_rivals_point_at_the_plugins_screen()
    {
        $this->ourTwoFaOn();
        $this->activate(['wp-2fa/wp-2fa.php', 'rublon/rublon2factor.php']);

        $notice = RivalTwoFa::notice();

        $this->assertCount(2, $notice['names']);
        $this->assertStringContainsString('plugins.php', $notice['url']);
    }

    /**
     * Every confirmed rival is a breakage, including the ones this plugin used to ask to
     * stand aside. That stand-down is gone (see RivalTwoFa): it never worked on Two Factor,
     * which forces its email provider back on rather than fail open, so a notice that called
     * this one handled was telling the owner their logins worked when they did not.
     */
    public function test_a_rival_that_publishes_a_hook_is_still_a_conflict()
    {
        $this->ourTwoFaOn();
        $this->rival([
            'plugin'  => 'two-factor/two-factor.php',
            'name'    => 'Two Factor',
            'classes' => [self::class],
            'enabled' => function () { return true; }
        ]);

        $notice = RivalTwoFa::notice();

        $this->assertNotNull($notice);
        $this->assertSame(['Two Factor'], $notice['names']);
    }

    /**
     * Nothing is left that could report a conflict as harmless. The screen draws one state,
     * so a `blocking` flag coming back would be a half-removed feature rather than a choice.
     */
    public function test_the_notice_no_longer_grades_a_conflict()
    {
        $this->ourTwoFaOn();
        $this->rival([
            'plugin'  => 'two-factor/two-factor.php',
            'name'    => 'Two Factor',
            'classes' => [self::class],
            'enabled' => function () { return true; }
        ]);

        $this->assertArrayNotHasKey('blocking', RivalTwoFa::notice());
    }

    /* --------------------------------------------- how a plugin is found and asked */

    /**
     * A constant is better evidence than a path. The entry in `active_plugins` names a
     * folder, so renaming it - or installing the same plugin as an mu-plugin - hides a plugin
     * that is still there and still hooking `wp_login`.
     */
    public function test_a_plugin_is_found_by_its_constant_with_no_entry_in_active_plugins()
    {
        define('FLS_TEST_RIVAL_CONSTANT', '1.0');

        $this->ourTwoFaOn();
        $this->rival(['constants' => ['FLS_TEST_RIVAL_CONSTANT']]);

        $this->assertSame(['Made Up Security'], RivalTwoFa::notice()['names']);
    }

    public function test_a_plugin_is_found_by_a_loaded_class()
    {
        $this->ourTwoFaOn();
        $this->rival(['classes' => [self::class]]);

        $this->assertNotNull(RivalTwoFa::notice());
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

        $this->assertNotNull(RivalTwoFa::notice());
    }

    /**
     * One install must not be reported as two products.
     *
     * Found on a real site: the full Wordfence plugin defines WORDFENCE_LS_VERSION, the
     * standalone Login Security plugin's own constant, because it ships the same code.
     */
    public function test_a_bundled_entry_stands_aside_for_the_product_that_ships_it()
    {
        define('FLS_TEST_SUITE_PRODUCT', '1.0');

        $this->ourTwoFaOn();

        add_filter('fluent_auth/2fa_conflict_plugins', function () {
            return [
                ['name' => 'The Bundled Part', 'constants' => ['FLS_TEST_SUITE_PRODUCT'], 'unless' => ['FLS_TEST_SUITE_PRODUCT']],
                ['name' => 'The Whole Suite', 'constants' => ['FLS_TEST_SUITE_PRODUCT']]
            ];
        });

        $this->assertSame(['The Whole Suite'], RivalTwoFa::notice()['names']);
    }

    /**
     * All-In-One Security bundles the same Simba library the standalone "Two Factor
     * Authentication" plugin is built from, and declares Simba_Two_Factor_Authentication_1
     * exactly as it does. Matching on that would name a plugin the site has not got.
     */
    public function test_the_shared_simba_library_is_not_mistaken_for_the_standalone_plugin()
    {
        $this->ourTwoFaOn();

        if (!class_exists('Simba_Two_Factor_Authentication_1', false)) {
            class_alias(self::class, 'Simba_Two_Factor_Authentication_1');
        }

        $this->assertNull(RivalTwoFa::notice());
    }

    public function test_a_plugin_that_says_its_second_factor_is_off_is_dropped()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () { return false; }]);

        $this->assertNull(RivalTwoFa::notice());
    }

    /**
     * "It will not say" is a third answer and has to stay one. Reading it as off drops a real
     * conflict silently; reading it as on warns a site about something unproven.
     */
    public function test_a_plugin_that_will_not_say_is_not_warned_about()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () { return null; }]);

        $this->assertNull(RivalTwoFa::notice());
    }

    /**
     * Their code runs inside our request. A getter that fatals on a version whose signature we
     * guessed wrong would otherwise take the settings screen with it.
     */
    public function test_a_plugin_whose_own_code_blows_up_is_not_warned_about()
    {
        $this->ourTwoFaOn();
        $this->activate(['made-up/made-up.php']);
        $this->rival(['enabled' => function () {
            /* An Error, not an Exception - which is what a bad call actually raises. */
            return \NoSuchClassAnywhere::answer();
        }]);

        $this->assertNull(RivalTwoFa::notice());
    }

    /**
     * An option that is not there is the shape a wrong option name takes. Reading it as
     * "switched off" is the one failure that loses a real conflict rather than softening it,
     * so absent answers neither yes nor no.
     */
    public function test_an_option_reports_absent_apart_from_false()
    {
        delete_option('fls_stub_flag');
        $this->assertNull(RivalTwoFa::optionSays('fls_stub_flag'));

        update_option('fls_stub_flag', 0);
        $this->assertFalse(RivalTwoFa::optionSays('fls_stub_flag'));

        update_option('fls_stub_flag', 1);
        $this->assertTrue(RivalTwoFa::optionSays('fls_stub_flag'));

        delete_option('fls_stub_flag');
    }

    /**
     * The two-hop shape these are published in: a static accessor handing back the live
     * controller, and the question asked of that. Wordfence counts enrolled users this way.
     */
    public function test_an_object_accessor_is_followed_and_asked()
    {
        $this->assertSame(7, RivalTwoFa::pluginObjectSays(RivalStubController::class, 'shared', 'active_count'));
        $this->assertNull(RivalTwoFa::pluginObjectSays(RivalStubController::class, 'no_such_accessor', 'active_count'));
        /* A method renamed between versions must read as "will not say", not as an answer. */
        $this->assertNull(RivalTwoFa::pluginObjectSays(RivalStubController::class, 'shared', 'renamed_away'));
    }

    /**
     * Defender publishes its switch as a public property on a model that hydrates itself, so
     * the object is the answer and there is no accessor to call.
     */
    public function test_a_settings_model_property_is_read()
    {
        $this->assertTrue(RivalTwoFa::pluginModelSays(RivalStubSettings::class, 'enabled'));
        $this->assertNull(RivalTwoFa::pluginModelSays(RivalStubSettings::class, 'no_such_property'));
        $this->assertNull(RivalTwoFa::pluginModelSays('No\\Such\\Model', 'enabled'));
    }
}

/**
 * Stand-ins for the two shapes these plugins publish their state in. Named for what they are
 * rather than after any one plugin: what is pinned is the reading, not the identifiers.
 */
class RivalStubController
{
    public static function shared()
    {
        return new self();
    }

    public function active_count()
    {
        return 7;
    }
}

class RivalStubSettings
{
    public $enabled = true;
}
