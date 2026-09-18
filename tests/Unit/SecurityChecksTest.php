<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\SecurityChecks;

class SecurityChecksTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        update_option('__fls_auth_settings', [
            'disable_xmlrpc'          => 'no',
            'disable_users_rest'      => 'no',
            'secure_signup_form'      => 'no',
            'login_try_limit'         => 5,
            'login_try_timing'        => 30,
            'auto_delete_logs_day'    => 30,
            'notification_user_roles' => [],
            'notification_email'      => '{admin_email}',
            'totp_2fa'                => 'no',
            'email2fa'                => 'no',
            'totp_required_roles'     => ['administrator'],
            'trusted_proxies'         => '10.0.0.0/8',
            'digest_summary'          => ''
        ]);

        Helper::resetStatics();
        delete_option('__fls_integrity_settings');
    }

    /**
     * @param string $key
     * @return array
     */
    private function item($key)
    {
        foreach (SecurityChecks::get()['items'] as $item) {
            if ($item['key'] === $key) {
                return $item;
            }
        }

        $this->fail('No security check named ' . $key);
    }

    /**
     * @param array $changes
     * @return void
     */
    private function settings($changes)
    {
        update_option('__fls_auth_settings', array_merge(get_option('__fls_auth_settings'), $changes));
        Helper::resetStatics();
    }

    /* ------------------------------------------------------------------ scoring */

    public function testOnlyTheUniversalRecommendationsAreScored()
    {
        $checklist = SecurityChecks::get();

        $scored = [];
        $unscored = [];

        foreach ($checklist['items'] as $item) {
            if ($item['scored']) {
                $scored[] = $item['key'];
            } else {
                $unscored[] = $item['key'];
            }
        }

        $this->assertEquals($checklist['total'], count($scored));

        // The ones with no right answer for every site must never count against one.
        $this->assertContains('integrity_scan', $unscored);
        $this->assertContains('notifications', $unscored);

        $this->assertContains('two_fa', $scored);
        $this->assertContains('disable_xmlrpc', $scored);
    }

    /**
     * Passkeys are a second factor, and leaving them out of this tally was a plain bug: a
     * site running the strongest method the plugin offers, and nothing else, was told it
     * had no second factor at all and docked the points - while the plugin's own
     * enforcement was accepting one as meeting a requirement.
     */
    public function testAPasskeyOnlySiteCountsAsHavingASecondFactor()
    {
        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        $this->assertSame('todo', $this->item('two_fa')['state'], 'The premise: nothing is on yet.');

        $this->settings(['passkey_2fa' => 'yes']);

        $this->assertSame('done', $this->item('two_fa')['state']);
    }

    /**
     * The switch is not enough on its own. Over plain http no passkey can be created
     * whatever the setting says, so ticking this off would score the site as holding a
     * factor nobody on it can register - see PasskeyTwoFaMethod::isSwitchedOn().
     */
    public function testAPasskeySwitchDoesNotCountOnASiteWithoutHttps()
    {
        update_option('home', 'http://example.org');
        update_option('siteurl', 'http://example.org');

        $this->settings(['passkey_2fa' => 'yes']);

        $this->assertSame('todo', $this->item('two_fa')['state']);

        // And the other methods still count there, since neither needs a secure context.
        $this->settings(['email2fa' => 'yes']);

        $this->assertSame('done', $this->item('two_fa')['state']);
    }

    public function testScoreCountsOnlyScoredItemsThatAreDone()
    {
        $this->assertEquals(0, SecurityChecks::get()['done']);

        $this->settings(['disable_xmlrpc' => 'yes', 'totp_2fa' => 'yes']);

        $this->assertEquals(2, SecurityChecks::get()['done']);

        // Satisfying an unscored item must not move the score.
        $this->settings(['notification_user_roles' => ['administrator'], 'notification_email' => '{admin_email}']);

        $this->assertEquals(2, SecurityChecks::get()['done']);
    }

    public function testTheScoreIsReachable()
    {
        $this->settings([
            'disable_xmlrpc'          => 'yes',
            'disable_users_rest'      => 'yes',
            'secure_signup_form'      => 'yes',
            'totp_2fa'                => 'yes',
            'notification_user_roles' => ['administrator']
        ]);

        $checklist = SecurityChecks::get();

        $this->assertEquals($checklist['total'], $checklist['done']);
    }

    /**
     * Every value a check writes has to come from the recommended map, or the checklist and
     * the "apply recommended" button can drift apart again.
     */
    public function testEveryScoredCheckIsSatisfiedByApplyingTheRecommendedSettings()
    {
        $this->settings(Helper::getRecommendedSettings());

        foreach (SecurityChecks::get()['items'] as $item) {
            if ($item['scored']) {
                $this->assertEquals('done', $item['state'], $item['key']);
            }
        }
    }

    public function testRecommendedSettingsLeaveTheJudgementCallsAlone()
    {
        $recommended = Helper::getRecommendedSettings();

        $this->assertArrayNotHasKey('disable_app_login', $recommended);
        $this->assertArrayNotHasKey('totp_required_roles', $recommended);
        $this->assertArrayNotHasKey('trusted_proxies', $recommended);
        $this->assertArrayNotHasKey('proxy_ip_header', $recommended);
    }

    /* -------------------------------------------------------------------- apply */

    public function testApplyTurnsOnJustThatCheck()
    {
        $result = SecurityChecks::apply('disable_xmlrpc');

        $this->assertIsArray($result);
        $this->assertEquals('yes', $result['settings']['disable_xmlrpc']);
        $this->assertEquals('done', $this->item('disable_xmlrpc')['state']);

        // And nothing else moved.
        $this->assertEquals('no', $result['settings']['disable_users_rest']);
        $this->assertEquals('no', $result['settings']['secure_signup_form']);
    }

    /**
     * Saving replaces the whole option, so a check that wrote only its own keys would erase
     * every other setting on the site.
     */
    public function testApplyPreservesSettingsItDoesNotTouch()
    {
        SecurityChecks::apply('disable_xmlrpc');

        $settings = get_option('__fls_auth_settings');

        $this->assertEquals(30, $settings['auto_delete_logs_day']);
        $this->assertEquals(5, $settings['login_try_limit']);
        $this->assertEquals('10.0.0.0/8', $settings['trusted_proxies']);
        $this->assertEquals(['administrator'], $settings['totp_required_roles']);
    }

    public function testApplyReturnsTheRecalculatedChecklist()
    {
        $before = SecurityChecks::get()['done'];

        $result = SecurityChecks::apply('disable_users_rest');

        $this->assertEquals($before + 1, $result['checklist']['done']);
    }

    public function testApplyingTwoFaAllowsItWithoutRequiringIt()
    {
        SecurityChecks::apply('two_fa');

        $settings = get_option('__fls_auth_settings');

        /*
         * Emailed codes, not the authenticator app. One click has to leave a site with a
         * second factor its users can actually reach, and an app nobody has been told
         * about is a switch that protects the people who already knew to look for it.
         * See Helper::getRecommendedSettings().
         */
        $this->assertEquals('yes', $settings['email2fa']);
        $this->assertEquals('no', $settings['totp_2fa']);
        $this->assertNotEmpty($settings['email2fa_roles']);
        // Requiring a factor is what locks people out, so a one-click button must not.
        $this->assertEquals(['administrator'], $settings['totp_required_roles']);
    }

    /**
     * apply() writes every key in a definition's `settings` list, so that list is not a
     * "what this item watches" note - it is the set of switches the button throws. The
     * two-factor item counts passkeys towards `done` but must not turn them on: the
     * recommended settings do not, so doing it here would leave this button and "Apply
     * recommended" disagreeing, and over plain http it would store a factor nobody on the
     * site can register.
     */
    public function testApplyingTwoFaDoesNotTurnOnPasskeys()
    {
        $settings = get_option('__fls_auth_settings');
        $settings['passkey_2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        SecurityChecks::apply('two_fa');

        $this->assertEquals('no', get_option('__fls_auth_settings')['passkey_2fa']);
    }

    /**
     * The general guard behind the case above: a one-click button may only write keys the
     * recommended settings have an opinion on. Anything else falls back to 'yes' in apply()
     * and switches on something nobody chose.
     */
    public function testNoCheckWritesASettingTheRecommendationsDoNotCover()
    {
        $recommended = Helper::getRecommendedSettings();

        $definitions = new \ReflectionMethod(SecurityChecks::class, 'definitions');
        $definitions->setAccessible(true);

        foreach ($definitions->invoke(null) as $key => $definition) {
            foreach ($definition['settings'] as $settingKey) {
                $this->assertArrayHasKey(
                    $settingKey,
                    $recommended,
                    sprintf('Check "%s" writes "%s", which getRecommendedSettings() does not cover.', $key, $settingKey)
                );
            }
        }
    }

    public function testApplyRefusesAnUnknownCheck()
    {
        $this->assertWpErrorWithCode(SecurityChecks::apply('disable_admin_bar'), 'unknown_check');
        $this->assertWpErrorWithCode(SecurityChecks::apply(''), 'unknown_check');
    }

    public function testApplyRefusesWhatItCannotTurnOnFromHere()
    {
        $this->assertWpErrorWithCode(SecurityChecks::apply('integrity_scan'), 'not_applicable');
    }

    public function testApplyRefusesWhatIsAlreadyOn()
    {
        $this->settings(['disable_xmlrpc' => 'yes']);

        $this->assertWpErrorWithCode(SecurityChecks::apply('disable_xmlrpc'), 'already_done');
    }
}
