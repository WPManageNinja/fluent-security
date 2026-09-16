<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Http\Controllers\SettingsController;
use FluentAuth\App\Http\Controllers\TwoFaController;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;

/**
 * The administration side of two factor: saving a policy, and the panel that answers
 * "who has this turned on" and "get this person back in".
 */
class TwoFaAdminTest extends BaseTestCase
{
    private $admin;

    public function setUp(): void
    {
        parent::setUp();

        $this->admin = $this->factory->user->create_and_get(['role' => 'administrator']);
        wp_set_current_user($this->admin->ID);

        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'yes';
        $settings['totp_2fa_roles'] = ['administrator'];
        $settings['totp_required_roles'] = [];
        $settings['email2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        wp_set_current_user(0);
        parent::tearDown();
    }

    private function save($overrides)
    {
        $request = new \WP_REST_Request();
        $request->set_param('settings', array_merge(Helper::getAuthSettings(), $overrides));

        $result = SettingsController::updateSettings($request);

        Helper::resetStatics();

        return $result;
    }

    /* ---------------------------------------------------------------------
     * Saving the policy
     * ------------------------------------------------------------------ */

    public function testThePolicyIsSaved()
    {
        $result = $this->save([
            'totp_2fa'            => 'yes',
            'totp_2fa_roles'      => ['administrator', 'editor'],
            'totp_required_roles' => ['administrator']
        ]);

        $this->assertNotWPError($result);
        $this->assertSame(['administrator', 'editor'], Helper::getSetting('totp_2fa_roles'));
        $this->assertSame(['administrator'], Helper::getSetting('totp_required_roles'));
    }

    /**
     * Both of the rules that used to guard this are gone, and their absence is the
     * feature. They existed because requiring a factor did not grant the means to get
     * one, so the two lists could disagree and the disagreement locked a role out.
     * Requiring now grants, so there is nothing left to refuse - and refusing here was
     * how an owner ended up with a requirement that silently did nothing.
     */
    public function testARoleCanBeRequiredWithoutAppearingInTheAllowList()
    {
        $result = $this->save([
            'totp_2fa'            => 'yes',
            'totp_2fa_roles'      => ['editor'],
            'totp_required_roles' => ['administrator']
        ]);

        $this->assertNotWPError($result);
        $this->assertSame(['administrator'], Helper::getSetting('totp_required_roles'));
    }

    public function testARoleCanBeRequiredWhileTheMethodIsOff()
    {
        $result = $this->save([
            'totp_2fa'            => 'no',
            'totp_required_roles' => ['administrator']
        ]);

        $this->assertNotWPError($result);
        $this->assertSame(['administrator'], Helper::getSetting('totp_required_roles'));
    }

    public function testTheRequiredLevelDefaultsToTheStrongReading()
    {
        $this->save(['totp_required_roles' => ['administrator']]);

        $this->assertSame('device', Helper::getSetting('two_fa_required_level'));
    }

    public function testAnUnknownRequiredLevelFallsBackToDevice()
    {
        $this->save([
            'totp_required_roles'   => ['administrator'],
            'two_fa_required_level' => 'whatever'
        ]);

        $this->assertSame('device', Helper::getSetting('two_fa_required_level'));
    }

    public function testTheRequiredLevelCanBeRelaxed()
    {
        $this->save([
            'totp_required_roles'   => ['administrator'],
            'two_fa_required_level' => 'any'
        ]);

        $this->assertSame('any', Helper::getSetting('two_fa_required_level'));
    }

    public function testEmailCodesStillNeedARole()
    {
        $result = $this->save([
            'email2fa'       => 'yes',
            'email2fa_roles' => []
        ]);

        $this->assertWPError($result);
        $this->assertArrayHasKey('email2fa_roles', $result->get_error_data());
    }

    /**
     * Saving writes the payload over the whole option, so a key the payload leaves out
     * falls back to its default rather than keeping what was stored. That is the trap
     * the "apply recommended settings" button used to fall into: it sent a fresh object
     * that happened not to mention the digest schedule, silently resetting it.
     *
     * Pinned here because the fix lives in the screen that builds the payload, which
     * means nothing on this side would notice it being reintroduced.
     */
    public function testAKeyMissingFromThePayloadFallsBackToItsDefault()
    {
        $this->save(['digest_summary' => 'monthly']);
        $this->assertSame('monthly', Helper::getSetting('digest_summary'));

        $settings = Helper::getAuthSettings();
        unset($settings['digest_summary']);

        $request = new \WP_REST_Request();
        $request->set_param('settings', $settings);

        $this->assertNotWPError(SettingsController::updateSettings($request));
        Helper::resetStatics();

        $this->assertSame('', Helper::getSetting('digest_summary'));
    }

    /* ---------------------------------------------------------------------
     * The enrollment panel
     * ------------------------------------------------------------------ */

    /**
     * The screen hides the table when no method is live, so this is what it decides on.
     * Switched on and offered to no role is switched on for nobody.
     */
    public function testItReportsWhichMethodsAreActuallyInForce()
    {
        $request = new \WP_REST_Request();

        $this->assertSame(
            ['totp' => true, 'email' => false, 'passkey' => false],
            TwoFaController::getUsers($request)['methods']
        );

        $this->save(['totp_2fa' => 'yes', 'totp_2fa_roles' => [], 'totp_required_roles' => []]);

        $this->assertFalse(
            TwoFaController::getUsers($request)['methods']['totp'],
            'Offered to nobody is not in force.'
        );

        $this->save(['email2fa' => 'yes', 'email2fa_roles' => ['subscriber']]);

        $this->assertTrue(TwoFaController::getUsers($request)['methods']['email']);
    }

    /**
     * The list is for the people a second factor applies to. A membership site has
     * thousands of subscribers offered nothing, and listing them buries the rows worth
     * reading under pages of "Not available".
     */
    public function testItLeavesOutUsersNoMethodApplesTo()
    {
        $outsider = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $ids = array_column(TwoFaController::getUsers(new \WP_REST_Request())['users']['data'], 'id');

        $this->assertContains($this->admin->ID, $ids, 'Their role is allowed an authenticator app.');
        $this->assertNotContains($outsider->ID, $ids);
    }

    public function testItIncludesRolesCoveredByEmailedCodesToo()
    {
        $subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $this->save(['email2fa' => 'yes', 'email2fa_roles' => ['subscriber']]);

        $ids = array_column(TwoFaController::getUsers(new \WP_REST_Request())['users']['data'], 'id');

        $this->assertContains($subscriber->ID, $ids);
    }

    /**
     * Somebody who enrolled while their role was allowed keeps a working secret after
     * the role is taken off the list, and this screen is the only place to turn it off.
     * Dropping them would leave the count above the table reporting a row it cannot show.
     */
    public function testItKeepsAnEnrolledUserWhoseRoleIsNoLongerAllowed()
    {
        $former = $this->factory->user->create_and_get(['role' => 'subscriber']);
        TotpTwoFaMethod::activate($former, TotpProvider::generateSecret());

        $ids = array_column(TwoFaController::getUsers(new \WP_REST_Request())['users']['data'], 'id');

        $this->assertContains($former->ID, $ids);
    }

    /**
     * The count over the table measures the policy landing, so it counts the people the
     * policy applies to rather than everyone with an account.
     */
    public function testTheSummaryCountsWhoCouldHaveOneRatherThanEverybody()
    {
        $this->factory->user->create_and_get(['role' => 'subscriber']);
        $this->factory->user->create_and_get(['role' => 'subscriber']);

        $summary = TwoFaController::getUsers(new \WP_REST_Request())['summary'];

        $administrators = (new \WP_User_Query(['role' => 'administrator', 'fields' => 'ID', 'number' => 1]))->get_total();
        $everybody = (new \WP_User_Query(['fields' => 'ID', 'number' => 1]))->get_total();

        $this->assertSame($administrators, $summary['eligible']);
        $this->assertLessThan(
            $everybody,
            $summary['eligible'],
            'Only administrators are allowed one here, so the two counts must not agree.'
        );
    }

    public function testItReportsWhoIsEnrolled()
    {
        TotpTwoFaMethod::activate($this->admin, TotpProvider::generateSecret());
        TotpTwoFaMethod::generateRecoveryCodes($this->admin);

        $request = new \WP_REST_Request();
        $result = TwoFaController::getUsers($request);

        $this->assertSame(1, $result['summary']['enrolled']);

        $row = null;
        foreach ($result['users']['data'] as $user) {
            if ($user['id'] === $this->admin->ID) {
                $row = $user;
            }
        }

        $this->assertNotNull($row);
        $this->assertTrue($row['totp_enrolled']);
        $this->assertSame(TotpTwoFaMethod::RECOVERY_CODE_COUNT, $row['recovery_codes']);
        $this->assertTrue($row['can_edit']);
    }

    /**
     * Enrollment lives in user meta, so this has to be a query rather than a filter over
     * whichever users happen to land on the first page.
     */
    public function testTheEnrolledFilterQueriesRatherThanFiltersThePage()
    {
        $other = $this->factory->user->create_and_get(['role' => 'subscriber']);
        TotpTwoFaMethod::activate($other, TotpProvider::generateSecret());

        $request = new \WP_REST_Request();
        $request->set_param('filter', 'enrolled');

        $result = TwoFaController::getUsers($request);

        $ids = array_column($result['users']['data'], 'id');

        $this->assertSame([$other->ID], $ids);
        $this->assertSame(1, $result['users']['total']);
    }

    public function testTheNotEnrolledFilterExcludesThem()
    {
        TotpTwoFaMethod::activate($this->admin, TotpProvider::generateSecret());

        $request = new \WP_REST_Request();
        $request->set_param('filter', 'not_enrolled');

        $result = TwoFaController::getUsers($request);

        $this->assertNotContains($this->admin->ID, array_column($result['users']['data'], 'id'));
    }

    /* ---------------------------------------------------------------------
     * Passkeys are a second factor too
     * ------------------------------------------------------------------ */

    /**
     * The row used to report on the authenticator app alone, so somebody holding a passkey
     * read as "Not set up" with a dash where their recovery codes are - on the one screen
     * an administrator goes to when that person cannot get in.
     */
    public function testAPasskeyHolderIsReportedAsHoldingSomething()
    {
        PasskeyStore::ensureTable();

        $this->setPasskeySettings();

        $target = $this->factory->user->create_and_get(['role' => 'administrator']);
        $this->enrolPasskey($target);
        TotpTwoFaMethod::generateRecoveryCodes($target);

        $row = $this->rowFor($target->ID);

        $this->assertNotNull($row);
        $this->assertFalse($row['totp_enrolled']);
        $this->assertSame(1, $row['passkey_count']);
        $this->assertTrue($row['passkey_allowed']);
        $this->assertSame(
            TotpTwoFaMethod::RECOVERY_CODE_COUNT,
            $row['recovery_codes'],
            'a passkey holder\'s recovery codes are the way back in, so the column has to carry them'
        );
    }

    /**
     * Where the whole of somebody's second factor can be read and - for a passkey, which
     * this endpoint cannot touch - removed.
     */
    public function testEachRowCarriesALinkToThatUsersProfile()
    {
        $row = $this->rowFor($this->admin->ID);

        $this->assertNotEmpty($row['profile_url']);
        $this->assertStringContainsString('#fls-two-factor', $row['profile_url']);
    }

    /**
     * The app's own permission is filterable, so it is not necessarily one that carries any
     * right over other people's accounts - and this endpoint answers with their names and
     * email addresses.
     */
    public function testTheListIsRefusedToSomeoneWhoCannotListUsers()
    {
        $callback = $this->permissionCallbackFor('/fluent-auth/two-fa/users');

        $this->assertNotNull($callback);

        wp_set_current_user($this->factory->user->create(['role' => 'editor']));
        $this->assertFalse(current_user_can('list_users'));
        $this->assertFalse(call_user_func($callback, new \WP_REST_Request()));

        wp_set_current_user($this->admin->ID);
        $this->assertTrue(call_user_func($callback, new \WP_REST_Request()));
    }

    public function testAnAdminCanTurnOffALostDevice()
    {
        $target = $this->factory->user->create_and_get(['role' => 'subscriber']);
        TotpTwoFaMethod::activate($target, TotpProvider::generateSecret());

        $request = new \WP_REST_Request();
        $request->set_param('id', $target->ID);

        $result = TwoFaController::resetUser($request);

        $this->assertNotWPError($result);
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($target->ID));
        $this->assertSame(0, $result['summary']['enrolled']);
    }

    /**
     * The endpoint's own permission is manage_options, but turning a second factor off
     * is the one action here that weakens an account, so it re-checks against that
     * specific user rather than trusting the door it came through.
     */
    public function testSomeoneWhoCannotEditTheUserCannotResetThem()
    {
        $target = $this->factory->user->create_and_get(['role' => 'administrator']);
        TotpTwoFaMethod::activate($target, TotpProvider::generateSecret());

        wp_set_current_user($this->factory->user->create(['role' => 'subscriber']));

        $request = new \WP_REST_Request();
        $request->set_param('id', $target->ID);

        $result = TwoFaController::resetUser($request);

        $this->assertWPError($result);
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($target->ID));
    }

    public function testResettingSomeoneWithNothingSetUpIsRefused()
    {
        $target = $this->factory->user->create_and_get(['role' => 'subscriber']);

        $request = new \WP_REST_Request();
        $request->set_param('id', $target->ID);

        $this->assertWPError(TwoFaController::resetUser($request));
    }

    public function testAMissingUserIsRefused()
    {
        $request = new \WP_REST_Request();
        $request->set_param('id', 99999999);

        $this->assertWPError(TwoFaController::resetUser($request));
    }

    /* ---------------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------------ */

    private function setPasskeySettings()
    {
        /* The fixture's ceremonies are signed for this origin - see WebAuthnFixture. */
        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        $settings = Helper::getAuthSettings();
        $settings['passkey_2fa'] = 'yes';
        $settings['passkey_2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function enrolPasskey($user)
    {
        $authenticator = new WebAuthnFixture();
        $challenge = random_bytes(32);
        $response = $authenticator->createRegistrationResponse(['challenge' => $challenge]);

        PasskeyStore::add($user, Registration::verify($response, $challenge), 'Test key');
    }

    private function rowFor($userId)
    {
        $result = TwoFaController::getUsers(new \WP_REST_Request());

        foreach ($result['users']['data'] as $row) {
            if ($row['id'] === $userId) {
                return $row;
            }
        }

        return null;
    }

    /**
     * The permission_callback the route was actually registered with, rather than a copy of
     * the rule written out here - a test of its own copy passes whatever the routes file says.
     */
    private function permissionCallbackFor($route)
    {
        foreach (rest_get_server()->get_routes() as $path => $handlers) {
            if ($path !== $route) {
                continue;
            }

            foreach ($handlers as $handler) {
                if (!empty($handler['permission_callback'])) {
                    return $handler['permission_callback'];
                }
            }
        }

        return null;
    }
}
