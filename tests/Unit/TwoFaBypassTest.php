<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaReminderHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaBypassHandler;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaBypass;
use FluentAuth\App\Services\TwoFa\TwoFaService;

/**
 * The documented way back in when a second factor cannot be answered.
 *
 * Driven through the value filter rather than by define()ing the constant: a constant
 * defined in one test is defined for every test that follows it in the same process,
 * and this one would quietly switch two-factor authentication off for the whole suite.
 */
class TwoFaBypassTest extends BaseTestCase
{
    private $admin;

    private $other;

    public function setUp(): void
    {
        parent::setUp();

        $this->admin = $this->factory->user->create_and_get([
            'role'       => 'administrator',
            'user_login' => 'locked_out_admin',
            'user_email' => 'locked@example.org'
        ]);

        $this->other = $this->factory->user->create_and_get(['role' => 'administrator']);

        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['administrator'];
        $settings['totp_required_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/two_fa_bypass_value');
        remove_all_filters('fluent_auth/show_lockout_help');
        wp_set_current_user(0);
        parent::tearDown();
    }

    private function configure($value)
    {
        add_filter('fluent_auth/two_fa_bypass_value', function () use ($value) {
            return $value;
        });
    }

    private function enableHelp()
    {
        $settings = Helper::getAuthSettings();
        $settings['show_lockout_help'] = 'yes';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    /* ------------------------------------------------------------ what it reads */

    public function test_nothing_is_bypassed_by_default()
    {
        $this->assertFalse(TwoFaBypass::isConfigured());
        $this->assertFalse(TwoFaBypass::isActiveFor($this->admin));
    }

    public function test_boolean_true_covers_every_account()
    {
        $this->configure(true);

        $this->assertTrue(TwoFaBypass::isActiveFor($this->admin));
        $this->assertTrue(TwoFaBypass::isActiveFor($this->other));
    }

    /**
     * The named form is what the login screen offers, so it has to be the one that works
     * without thinking: whichever of the three identifiers somebody reaches for at two in
     * the morning is the one they have.
     */
    public function test_a_login_name_covers_only_that_account()
    {
        $this->configure('locked_out_admin');

        $this->assertTrue(TwoFaBypass::isActiveFor($this->admin));
        $this->assertFalse(TwoFaBypass::isActiveFor($this->other));
    }

    public function test_an_email_address_works_too()
    {
        $this->configure('locked@example.org');

        $this->assertTrue(TwoFaBypass::isActiveFor($this->admin));
    }

    public function test_a_user_id_works_too()
    {
        $this->configure((string)$this->admin->ID);

        $this->assertTrue(TwoFaBypass::isActiveFor($this->admin));
        $this->assertFalse(TwoFaBypass::isActiveFor($this->other));
    }

    public function test_names_are_matched_without_regard_to_case()
    {
        $this->configure('LOCKED_OUT_ADMIN');

        $this->assertTrue(TwoFaBypass::isActiveFor($this->admin));
    }

    public function test_several_accounts_can_be_named_at_once()
    {
        $this->configure('someone_else, locked_out_admin');

        $this->assertTrue(TwoFaBypass::isActiveFor($this->admin));
        $this->assertFalse(TwoFaBypass::isActiveFor($this->other));
    }

    public function test_an_unknown_name_covers_nobody()
    {
        $this->configure('not_a_real_account');

        $this->assertTrue(TwoFaBypass::isConfigured());
        $this->assertFalse(TwoFaBypass::isActiveFor($this->admin));
    }

    /**
     * A string is a name, never a truthiness. Reading 'false' or '0' as "switch it off
     * for everybody" would turn a typo into an unprotected site.
     */
    public function test_an_empty_value_is_not_a_bypass()
    {
        $this->configure('');
        $this->assertFalse(TwoFaBypass::isActiveFor($this->admin));

        $this->configure(false);
        $this->assertFalse(TwoFaBypass::isActiveFor($this->admin));
    }

    /* -------------------------------------------------------- what it lifts */

    public function test_it_lifts_a_challenge_the_user_cannot_answer()
    {
        TotpTwoFaMethod::activate($this->admin, TotpProvider::generateSecret());

        $this->assertInstanceOf(
            TotpTwoFaMethod::class,
            TwoFaService::getRequiredMethod($this->admin, []),
            'Precondition: this account is normally challenged.'
        );

        $this->configure('locked_out_admin');

        $this->assertNull(TwoFaService::getRequiredMethod($this->admin, []));
    }

    public function test_it_lifts_the_enrolment_requirement_too()
    {
        $this->assertTrue(DeviceRequirement::isOwedBy($this->admin));

        $this->configure('locked_out_admin');

        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
        $this->assertNull(TwoFaService::getRequiredMethod($this->admin, []));
    }

    /**
     * Lifting it at the login screen while still nagging the same person on every admin
     * screen would be a door unlocked onto a wall.
     *
     * There is nothing left to refuse - see TwoFaReminderHandler - so what the bypass has
     * to reach now is the reminder itself.
     */
    public function test_the_reminder_goes_quiet_for_a_bypassed_account()
    {
        wp_set_current_user($this->admin->ID);

        $reminder = new TwoFaReminderHandler();

        $this->assertTrue($reminder->owesDeviceFactor());

        $this->configure('locked_out_admin');

        $this->assertFalse($reminder->owesDeviceFactor());
    }

    public function test_it_lifts_nothing_for_an_account_it_does_not_name()
    {
        $this->configure('locked_out_admin');

        $this->assertTrue(DeviceRequirement::isOwedBy($this->other));
    }

    /* ----------------------------------------------------------- the offer */

    public function test_the_help_is_off_by_default_for_existing_settings()
    {
        $settings = Helper::getAuthSettings();
        unset($settings['show_lockout_help']);
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->assertSame('no', Helper::getSetting('show_lockout_help'));
        add_filter('fluent_auth/show_lockout_help', '__return_true');
        $this->assertSame('', TwoFaBypass::renderHelp($this->admin));
    }

    public function test_disabled_help_cannot_be_enabled_by_the_audience_filter()
    {
        add_filter('fluent_auth/show_lockout_help', '__return_true');

        $this->assertSame('', TwoFaBypass::renderHelp($this->admin));
    }

    public function test_the_help_names_the_account_looking_at_it()
    {
        $this->enableHelp();
        $html = TwoFaBypass::renderHelp($this->admin);

        $this->assertStringContainsString(TwoFaBypass::CONSTANT, $html);
        $this->assertStringContainsString('locked_out_admin', $html);
    }

    /**
     * Somebody who cannot edit wp-config.php is being handed instructions they cannot
     * follow in place of the only thing that helps them, which is who to ask.
     */
    public function test_the_help_is_not_offered_to_someone_who_could_not_act_on_it()
    {
        $this->enableHelp();
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $this->assertSame('', TwoFaBypass::renderHelp($subscriber));
    }

    public function test_the_help_stops_once_it_has_been_taken()
    {
        $this->enableHelp();
        $this->configure('locked_out_admin');

        $this->assertSame(
            '',
            TwoFaBypass::renderHelp($this->admin),
            'There is nothing left to instruct: they are already being let in.'
        );
    }

    public function test_the_help_is_collapsed_until_the_user_expands_it()
    {
        $this->enableHelp();
        $html = TwoFaBypass::renderHelp($this->admin);

        $this->assertStringContainsString('<details id="fls_lockout_help"', $html);
        $this->assertStringContainsString('Need help with your verification code?', $html);
        $this->assertDoesNotMatchRegularExpression('/<details\b[^>]*\bopen(?:\s|=|>)/i', $html);
        $this->assertStringNotContainsString('data-fls-delay', $html);
    }

    public function test_the_help_can_be_turned_off()
    {
        $this->enableHelp();
        add_filter('fluent_auth/show_lockout_help', '__return_false');

        $this->assertSame('', TwoFaBypass::renderHelp($this->admin));
    }

    /* ------------------------------------------------------------ the trail */

    /**
     * An emergency switch nobody is reminded of is an emergency switch that stays on.
     */
    public function test_a_bypassed_sign_in_is_written_to_the_log()
    {
        $this->configure('locked_out_admin');

        (new TwoFaBypassHandler())->maybeLogBypassedLogin($this->admin->user_login, $this->admin);

        $row = flsDb()->table('fls_auth_logs')
            ->where('user_id', $this->admin->ID)
            ->where('media', 'two_fa_bypassed')
            ->first();

        $this->assertNotNull($row);
        $this->assertSame('login', $row->status);
    }

    public function test_an_ordinary_sign_in_is_not_marked_as_bypassed()
    {
        (new TwoFaBypassHandler())->maybeLogBypassedLogin($this->admin->user_login, $this->admin);

        $row = flsDb()->table('fls_auth_logs')
            ->where('user_id', $this->admin->ID)
            ->where('media', 'two_fa_bypassed')
            ->first();

        $this->assertNull($row);
    }

    public function test_the_log_label_is_readable()
    {
        $this->assertNotSame(
            'two_fa_bypassed',
            Helper::getLoginMediaLabel('two_fa_bypassed'),
            'An unnamed media slug shows up raw in the log table.'
        );
    }

    public function test_the_notice_says_who_is_covered()
    {
        $this->configure('locked_out_admin');
        $this->assertSame('locked_out_admin', TwoFaBypass::describe());

        $this->configure(true);
        $this->assertNotSame('', TwoFaBypass::describe());
    }
}
