<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TotpEnforcementHandler;
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
     * The master switch governs who may set one up voluntarily. It does not cancel a
     * requirement - a site that says a role must hold a second factor while every method
     * is switched off used to mean nothing at all, which is the worst reading available.
     */
    public function testTurningTheMethodOffDoesNotCancelTheRequirement()
    {
        $this->policy('no', [], ['administrator']);

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
     * Enforcement
     * ------------------------------------------------------------------ */

    public function testAnUnenrolledRequiredUserIsGated()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $this->assertTrue((new TotpEnforcementHandler())->needsEnrollment());
    }

    public function testEnrollingClearsTheGate()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        TotpTwoFaMethod::activate($this->admin, TotpProvider::generateSecret());

        $this->assertFalse((new TotpEnforcementHandler())->needsEnrollment());
    }

    public function testAUserWhoseRoleIsNotRequiredIsNeverGated()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->subscriber->ID);

        $this->assertFalse((new TotpEnforcementHandler())->needsEnrollment());
    }

    public function testLoggedOutRequestsAreNeverGated()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user(0);

        $this->assertFalse((new TotpEnforcementHandler())->needsEnrollment());
    }

    /**
     * A redirect sent in reply to an ajax call breaks the caller instead of reaching
     * anybody, so the gate has to stay out of the way of them.
     */
    public function testAjaxRequestsAreNotRedirected()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        add_filter('wp_doing_ajax', '__return_true');

        $this->assertFalse((new TotpEnforcementHandler())->needsEnrollment());

        remove_filter('wp_doing_ajax', '__return_true');
    }

    /**
     * The gate shuts the admin area, so it cannot send people into the admin area to
     * get past it. On a site that keeps a role out of wp-admin altogether, a redirect
     * to their profile is a redirect straight back out again with nothing set up.
     */
    public function testTheGateSendsPeopleToTheStandaloneSetupScreen()
    {
        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $location = $this->captureRedirect(function () {
            (new TotpEnforcementHandler())->maybeForceEnrollment();
        });

        $this->assertStringContainsString('wp-login.php', (string)parse_url($location, PHP_URL_PATH));
        $this->assertStringNotContainsString('profile.php', $location);

        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);

        $this->assertSame(TotpSetupPageHandler::LOGIN_ACTION, $query['action']);
        $this->assertSame(
            admin_url(),
            urldecode($query['redirect_to']),
            'They were trying to use the admin area, so that is where finishing should return them.'
        );
    }

    public function testSomebodyAlreadyEnrollingOnTheirProfileIsLeftThere()
    {
        global $pagenow;

        $this->policy('yes', ['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $was = $pagenow;
        $pagenow = 'profile.php';

        $location = $this->captureRedirect(function () {
            (new TotpEnforcementHandler())->maybeForceEnrollment();
        });

        $pagenow = $was;

        $this->assertNull($location, 'Pulling somebody off the form mid-enrollment loses the pending secret.');
    }

    /**
     * maybeForceEnrollment() ends in exit(), so the redirect is intercepted at the
     * filter and unwound before it gets there.
     *
     * @param $callback callable
     * @return string|null where it tried to send the user, or null if it did not
     */
    private function captureRedirect($callback)
    {
        $captured = null;

        $catch = function ($location) use (&$captured) {
            $captured = $location;
            throw new \RuntimeException('redirected');
        };

        add_filter('wp_redirect', $catch);

        try {
            $callback();
        } catch (\RuntimeException $e) {
            // Expected: this is how the exit() below the redirect is escaped.
        } finally {
            remove_filter('wp_redirect', $catch);
        }

        return $captured;
    }
}
