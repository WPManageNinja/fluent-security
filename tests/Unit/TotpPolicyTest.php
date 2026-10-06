<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaReminderHandler;
use FluentAuth\App\Hooks\Handlers\TotpSetupPageHandler;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * The rules deciding who may set up an authenticator app and who has to.
 *
 * Both directions can hurt: too loose and the policy is decorative, too tight and it
 * shuts an administrator out of their own site. The cases that matter most here are
 * the ones where a setting is changed after people have already enrolled.
 */
class TotpPolicyTest extends BaseTestCase
{
    private $admin;

    private $subscriber;

    public function setUp(): void
    {
        parent::setUp();

        $this->admin = $this->factory->user->create_and_get(['role' => 'administrator']);
        $this->subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $this->policy('yes', [], []);
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/totp_enabled');
        wp_set_current_user(0);
        parent::tearDown();
    }

    private function policy($enabled, $allowed, $required)
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = $enabled;
        $settings['totp_2fa_roles'] = $allowed;
        $settings['totp_required_roles'] = $required;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    public function testItIsOffUntilSwitchedOn()
    {
        $this->policy('no', [], []);

        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->admin));
    }

    /**
     * Naming the roles is how the method is turned on. Read the other way, flipping the
     * switch alone would hand an authenticator app to every subscriber on the site.
     */
    public function testAnEmptyAllowListMeansNobodyRatherThanEveryRole()
    {
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    public function testNamingRolesRestrictsItToThem()
    {
        $this->policy('yes', ['administrator'], []);

        $this->assertTrue(TotpTwoFaMethod::isAllowedForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    public function testNobodyIsRequiredByDefault()
    {
        $this->assertFalse(TotpTwoFaMethod::isRequiredForUser($this->admin));
    }

    public function testARequiredRoleIsRequired()
    {
        $this->policy('yes', ['administrator'], ['administrator']);

        $this->assertTrue(TotpTwoFaMethod::isRequiredForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isRequiredForUser($this->subscriber));
    }

    /**
     * Requiring a role that is offered nothing is the locked-out case, and an empty
     * allow list offers nothing to anybody - so it cannot be the one shape of that
     * mistake the policy waves through.
     */
    /**
     * The old rule was that a role could not be required unless it was also allowed,
     * because requiring something the setup screen refused to offer was a lockout. That
     * is now handled the other way round: requiring a factor grants the methods that
     * satisfy it, so the two lists can no longer disagree and the requirement is what it
     * says it is.
     */
    public function testRequiringARoleAllowsItEvenWithAnEmptyAllowList()
    {
        $this->policy('yes', [], ['administrator']);

        $this->assertTrue(TotpTwoFaMethod::isRequiredForUser($this->admin));
        $this->assertTrue(
            TotpTwoFaMethod::isAllowedForUser($this->admin),
            'A policy that demands a factor has to offer the means to get one.'
        );
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    /**
     * The settings screen will not save this combination, but a filter or a direct
     * option write can still produce it - and demanding something the profile screen
     * refuses to offer is a locked out user, not a secured one.
     */
    public function testARequiredRoleIsOfferedTheMethodEvenIfTheAllowListNamesOthers()
    {
        $this->policy('yes', ['editor'], ['administrator']);

        $this->assertTrue(TotpTwoFaMethod::isRequiredForUser($this->admin));
        $this->assertTrue(TotpTwoFaMethod::isAllowedForUser($this->admin));
    }

    /**
     * The master switch governs the method for everybody, requirement included.
     *
     * A site with every method switched off has no second factor at all - so a
     * requirement standing over it is not a hidden policy, it is nothing. This is the
     * rule that keeps the settings screen honest: a method that reads off is off.
     */
    public function testTurningTheMethodOffCancelsTheRequirementItWasTheOnlyWayToMeet()
    {
        $this->policy('no', [], ['administrator']);

        $this->assertFalse(TotpTwoFaMethod::isRequiredForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    /**
     * Switched on, though, and the requirement reaches past the allow list - otherwise
     * the two could disagree, and the disagreement is a user who must hold a factor and
     * has no way to get one.
     */
    public function testTheRequirementStillReachesPastTheAllowListWhileTheMethodIsOn()
    {
        $this->policy('yes', [], ['administrator']);

        $this->assertTrue(TotpTwoFaMethod::isRequiredForUser($this->admin));
        $this->assertTrue(TotpTwoFaMethod::isAllowedForUser($this->admin));

        // ...and still off for everybody who was not required.
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    /**
     * Someone who enrolled while their role was allowed keeps a working secret, but the
     * method stops being asked for once the policy no longer covers them - otherwise
     * turning it off for a role would leave those users facing a factor the site says
     * they should not have.
     */
    public function testRemovingARoleStopsTheMethodBeingUsedByItsMembers()
    {
        $this->policy('yes', ['administrator'], []);

        TotpTwoFaMethod::activate($this->admin, TotpProvider::generateSecret());

        $method = new TotpTwoFaMethod();
        $this->assertTrue($method->isAvailableForUser($this->admin));

        $this->policy('yes', ['editor'], []);

        $this->assertFalse($method->isAvailableForUser($this->admin));
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($this->admin), 'The secret itself is left alone.');
    }

    public function testTheFilterStillOverridesEverything()
    {
        add_filter('fluent_auth/totp_enabled', '__return_false');

        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->admin));
    }

    /* ---------------------------------------------------------------------
     * The reminder
     * ------------------------------------------------------------------ */

    /**
     * What used to be an enforcement gate here is a notice now, and the notice is the
     * whole of what this plugin does to a session that predates the requirement. See
     * TwoFaReminderHandler for what was removed and why: the gate redirected users out
     * of every admin page and refused admin-ajax and REST wholesale, which broke
     * ordinary site traffic for the sake of a window that closes at the next sign-in.
     *
     * The requirement itself is unchanged - it is applied during login, by
     * EnrollmentTwoFaMethod, before a cookie exists.
     */
    public function testAnUnenrolledRequiredUserIsReminded()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $this->assertTrue((new TwoFaReminderHandler())->owesDeviceFactor());
    }

    public function testEnrollingStopsTheReminder()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        TotpTwoFaMethod::activate($this->admin, TotpProvider::generateSecret());

        $this->assertFalse((new TwoFaReminderHandler())->owesDeviceFactor());
    }

    public function testAUserWhoseRoleIsNotRequiredIsNeverReminded()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->subscriber->ID);

        $this->assertFalse((new TwoFaReminderHandler())->owesDeviceFactor());
    }

    public function testLoggedOutRequestsAreNeverReminded()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user(0);

        $this->assertFalse((new TwoFaReminderHandler())->owesDeviceFactor());
    }

    /**
     * The notice points at the profile screen, which is where a passkey, an authenticator
     * app and recovery codes all live on one card. Anybody reading an admin notice is
     * already in wp-admin, so there is no reason to send them to the standalone page.
     */
    public function testTheNoticeSendsPeopleToTheirProfile()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        ob_start();
        (new TwoFaReminderHandler())->renderNotice();
        $html = ob_get_clean();

        $this->assertStringContainsString('profile.php', $html);
        $this->assertStringContainsString('notice', $html);
    }

    /**
     * Nothing is drawn for somebody who owes nothing - a warning on every admin screen of
     * a site that is already set up is just noise.
     */
    public function testNothingIsDrawnForSomebodyWhoOwesNothing()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->subscriber->ID);

        ob_start();
        (new TwoFaReminderHandler())->renderNotice();

        $this->assertSame('', trim(ob_get_clean()));
    }

}
