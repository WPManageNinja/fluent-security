<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Activator;
use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TotpEnforcementHandler;
use FluentAuth\App\Hooks\Handlers\TotpNudgeHandler;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\DeviceRequirement;
use FluentAuth\App\Services\TwoFa\EmailTwoFaMethod;
use FluentAuth\App\Services\TwoFa\EnrollmentTwoFaMethod;
use FluentAuth\App\Services\TwoFa\FactorStore;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;

/**
 * The rule that a role must hold a device factor, and where it is enforced.
 *
 * It used to be enforced on `admin_init`, which is after the auth cookie has been
 * issued - so the user it was holding back already had a working session and only the
 * dashboard was hidden from them. The tests that matter most here are the ones about
 * what happens *before* the cookie, because that is the whole of the fix.
 */
class DeviceEnrollmentGateTest extends BaseTestCase
{
    private $admin;

    private $subscriber;

    public function setUp(): void
    {
        parent::setUp();

        $this->admin = $this->factory->user->create_and_get(['role' => 'administrator']);
        $this->subscriber = $this->factory->user->create_and_get(['role' => 'subscriber']);
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/device_factor_required');
        remove_all_filters('fluent_auth/passkey_allow_without_fallback');
        wp_set_current_user(0);
        parent::tearDown();
    }

    /* ------------------------------------------------------------------ helpers */

    private function policy($allowed, $required, $enabled = 'yes')
    {
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = $enabled;
        $settings['totp_2fa_roles'] = $allowed;
        $settings['totp_required_roles'] = $required;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function enablePasskeys($roles = ['administrator'])
    {
        // Passkeys need a secure context; without one the method is off whatever the setting says.
        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        $settings = Helper::getAuthSettings();
        $settings['passkey_2fa'] = 'yes';
        $settings['passkey_2fa_roles'] = $roles;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function addPasskey($user, $credentialId)
    {
        return FactorStore::insert([
            'user_id'    => $user->ID,
            'type'       => FactorStore::TYPE_PASSKEY,
            'status'     => FactorStore::STATUS_ACTIVE,
            'identifier' => $credentialId,
            'secret'     => 'pem',
            'meta'       => ['algorithm' => -7]
        ]);
    }

    private function enrolTotp($user)
    {
        TotpTwoFaMethod::activate($user, TotpProvider::generateSecret());
    }

    private function setLevel($level)
    {
        $settings = Helper::getAuthSettings();
        $settings['two_fa_required_level'] = $level;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function enableEmail2Fa($roles = ['administrator'])
    {
        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = $roles;
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();
    }

    private function currentCode($secret)
    {
        return TotpProvider::getCodeForCounter($secret, (int)floor(time() / TotpProvider::PERIOD));
    }

    /* ------------------------------------------------- who owes a device factor */

    public function test_nobody_owes_anything_by_default()
    {
        $this->policy([], []);

        $this->assertFalse(DeviceRequirement::isRequiredForUser($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    public function test_a_named_role_owes_a_device_factor()
    {
        $this->policy(['administrator'], ['administrator']);

        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
        $this->assertTrue(DeviceRequirement::isOwedBy($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->subscriber));
    }

    /**
     * A method that is *on* is granted to the roles required to hold one, whatever its
     * own role list says. That is what stops the two lists disagreeing, and a
     * disagreement between them is a user who must hold a factor and cannot get one.
     */
    public function test_requiring_a_factor_grants_a_method_that_is_switched_on()
    {
        $this->policy([], ['administrator'], 'yes');

        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
        $this->assertTrue(
            TotpTwoFaMethod::isAllowedForUser($this->admin),
            'A demand with no way to meet it is a lockout.'
        );
        $this->assertTrue(DeviceRequirement::isOwedBy($this->admin));
    }

    /**
     * A method that is *off* is off for everybody, requirement included - and with
     * nothing left that could satisfy it, the requirement itself stops standing.
     *
     * The alternative was a settings screen on which three methods read off while two of
     * them were quietly on for the required roles. Requiring a second factor is a
     * statement about the methods; it cannot conjure one nobody enabled.
     */
    public function test_a_requirement_over_no_enabled_method_is_not_a_requirement()
    {
        $this->policy([], ['administrator'], 'no');

        $this->assertFalse(DeviceRequirement::isEnforceable());
        $this->assertFalse(DeviceRequirement::isRequiredForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    /**
     * The lockout this whole rule exists to avoid, and the one the first cut of it
     * created: a method is switched on, so the site reads as enforceable, but the
     * required role cannot reach it.
     */
    public function test_a_requirement_a_user_cannot_possibly_satisfy_does_not_stand()
    {
        $this->policy([], ['administrator'], 'no');   // app off
        $this->setLevel(DeviceRequirement::LEVEL_ANY);

        // Emailed codes on, but for a role the required user does not hold.
        $this->enableEmail2Fa(['editor']);

        $this->assertTrue(
            DeviceRequirement::isEnforceable(),
            'The site has an accepted method switched on.'
        );
        $this->assertFalse(
            DeviceRequirement::canBeSatisfiedBy($this->admin),
            'The administrator can reach none of it.'
        );
        $this->assertFalse(
            DeviceRequirement::isRequiredForUser($this->admin),
            'Requiring a factor of somebody who cannot obtain one is a locked out account.'
        );
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    /** ...and it stands again the moment that role can actually reach the method. */
    public function test_it_stands_once_the_required_role_can_reach_the_method()
    {
        $this->policy([], ['administrator'], 'no');
        $this->setLevel(DeviceRequirement::LEVEL_ANY);
        $this->enableEmail2Fa(['administrator']);

        $this->assertTrue(DeviceRequirement::canBeSatisfiedBy($this->admin));
        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
    }

    /**
     * A device method is granted by the requirement, so being switched on is enough -
     * its own role list is not consulted for a required user.
     */
    public function test_a_switched_on_device_method_satisfies_without_its_role_list()
    {
        $this->policy([], ['administrator'], 'yes');   // app on, allow list empty

        $this->assertTrue(DeviceRequirement::canBeSatisfiedBy($this->admin));
        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
        $this->assertTrue(TotpTwoFaMethod::isAllowedForUser($this->admin));
    }

    /**
     * The enrolment screen must never pair something that cannot then count. It used to:
     * the app activated, the requirement was still owed, and the next sign-in
     * regenerated the secret and killed the app the user had just set up.
     */
    public function test_the_enrolment_step_refuses_an_app_that_is_switched_off()
    {
        $this->enablePasskeys(['administrator']);
        $this->policy([], ['administrator'], 'no');   // passkeys on, app off

        $this->assertTrue(DeviceRequirement::isOwedBy($this->admin), 'still owed a device factor');
        $this->assertFalse(
            EnrollmentTwoFaMethod::canOfferTotp($this->admin),
            'the app is off, so the screen must not offer it'
        );
        $this->assertTrue(
            EnrollmentTwoFaMethod::canOfferPasskey($this->admin),
            'the passkey is what they are meant to use'
        );
    }

    /** Switching any one of them back on is enough to make the requirement stand again. */
    public function test_enabling_a_method_makes_the_requirement_stand_again()
    {
        $this->policy([], ['administrator'], 'no');
        $this->assertFalse(DeviceRequirement::isRequiredForUser($this->admin));

        $this->enablePasskeys([]);

        $this->assertTrue(DeviceRequirement::isEnforceable());
        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
    }

    /**
     * The device floor does not accept an emailed code, so a site with only email codes
     * on has nothing that meets it.
     */
    public function test_email_codes_alone_do_not_make_a_device_requirement_enforceable()
    {
        $this->policy([], ['administrator'], 'no');

        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $this->setLevel(DeviceRequirement::LEVEL_DEVICE);
        $this->assertFalse(DeviceRequirement::isEnforceable());

        // ...but they do at the floor that accepts them.
        $this->setLevel(DeviceRequirement::LEVEL_ANY);
        $this->assertTrue(DeviceRequirement::isEnforceable());
    }

    public function test_granting_reaches_only_the_roles_that_were_required()
    {
        $this->policy([], ['administrator'], 'yes');

        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    /**
     * A site can still veto a method for a particular user outright. That is site code
     * making a deliberate statement about one account, and a requirement should not talk
     * over it - `fluent_auth/device_factor_required` is the matching way to lift the
     * requirement itself.
     */
    public function test_a_per_user_veto_still_beats_the_grant()
    {
        $this->policy([], ['administrator'], 'no');

        add_filter('fluent_auth/totp_enabled', '__return_false');

        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->admin));

        remove_filter('fluent_auth/totp_enabled', '__return_false');
    }

    /* ------------------------------------------------------ enrolling a passkey */

    /**
     * The passkey is offered alongside the app rather than instead of it, so the browser
     * gets to decide. Both challenges are raised when the login is held, because there is
     * no session yet in which to ask for a second one.
     */
    public function test_a_passkey_challenge_is_raised_alongside_the_app_secret()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $raised = (new TwoFaHandler())->sendAndGet2FaConfirmFormUrl($this->admin, 'both');

        $row = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $raised['login_hash'])
            ->first();

        $this->assertNotEmpty($row->{EnrollmentTwoFaMethod::CHALLENGE_COLUMN});
        $this->assertNotEmpty(TotpTwoFaMethod::getPendingSecret($this->admin->ID));
    }

    /**
     * On a site that cannot do passkeys at all - plain http, say - the offer must not
     * appear, or the screen shows a button that cannot work.
     */
    public function test_no_passkey_challenge_is_raised_where_passkeys_are_impossible()
    {
        $this->policy(['administrator'], ['administrator']);

        $raised = (new TwoFaHandler())->sendAndGet2FaConfirmFormUrl($this->admin, 'both');

        $row = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $raised['login_hash'])
            ->first();

        $this->assertEmpty($row->{EnrollmentTwoFaMethod::CHALLENGE_COLUMN});

        $html = (new EnrollmentTwoFaMethod())->renderForm(['login_hash' => $raised['login_hash']]);

        $this->assertStringNotContainsString('fls_enroll_passkey_start', $html);
        $this->assertStringContainsString('fls_enroll_code', $html);
    }

    public function test_the_form_offers_both_routes_where_passkeys_are_possible()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $raised = (new TwoFaHandler())->sendAndGet2FaConfirmFormUrl($this->admin, 'both');

        $html = (new EnrollmentTwoFaMethod())->renderForm(['login_hash' => $raised['login_hash']]);

        $this->assertStringContainsString('fls_enroll_passkey_start', $html);
        $this->assertStringContainsString('fls_enroll_code', $html);

        /*
         * The platform probe that decides which of the two leads runs in
         * login_helper.js; what the form owes it is the creation options. Asserted as
         * data rather than as a JS symbol in the markup, because the markup is also
         * delivered to the front end as a string and installed with innerHTML, which
         * would never have run a script here anyway.
         */
        $this->assertMatchesRegularExpression(
            '#<script type="application/json" id="fls_enroll_config">#',
            $html
        );

        preg_match('#id="fls_enroll_config">(.*?)</script>#s', $html, $matches);
        $config = json_decode(trim($matches[1]), true);

        $this->assertNotEmpty($config['options']['challenge']);
        $this->assertNotEmpty($config['options']['user']['id']);
    }

    public function test_a_passkey_completes_the_enrolment_and_clears_the_requirement()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $method = new EnrollmentTwoFaMethod();
        $challenge = $this->raisePasskeyChallenge($method);

        $authenticator = new WebAuthnFixture();
        $response = $authenticator->createRegistrationResponse(['challenge' => $challenge]);

        $result = $method->verifyProof($this->admin, $this->rowWithChallenge($challenge), [
            'fls_enroll_credential' => wp_slash(json_encode($response))
        ]);

        $this->assertTrue($result);
        $this->assertSame(1, PasskeyStore::countForUser($this->admin));

        // Recovery codes are what let a single passkey stand on its own.
        $method->getSuccessResponse(['redirect' => '/'], $this->admin, (object)[]);

        $this->assertGreaterThan(0, RecoveryCodes::countRemaining($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    public function test_a_passkey_answering_a_different_challenge_is_refused()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $method = new EnrollmentTwoFaMethod();
        $this->raisePasskeyChallenge($method);

        $authenticator = new WebAuthnFixture();
        $response = $authenticator->createRegistrationResponse(['challenge' => random_bytes(32)]);

        $result = $method->verifyProof($this->admin, $this->rowWithChallenge(random_bytes(32)), [
            'fls_enroll_credential' => wp_slash(json_encode($response))
        ]);

        $this->assertWpErrorWithCode($result, 'passkey_unverified');
        $this->assertSame(0, PasskeyStore::countForUser($this->admin));
    }

    public function test_an_unreadable_passkey_response_is_a_hard_error()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $method = new EnrollmentTwoFaMethod();
        $challenge = $this->raisePasskeyChallenge($method);

        $result = $method->verifyProof($this->admin, $this->rowWithChallenge($challenge), [
            'fls_enroll_credential' => 'not json'
        ]);

        $this->assertWpErrorWithCode($result, 'invalid_credential');
    }

    public function test_a_passkey_is_refused_where_the_row_carries_no_challenge()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $authenticator = new WebAuthnFixture();
        $response = $authenticator->createRegistrationResponse(['challenge' => random_bytes(32)]);

        $result = (new EnrollmentTwoFaMethod())->verifyProof($this->admin, (object)[], [
            'fls_enroll_credential' => wp_slash(json_encode($response))
        ]);

        $this->assertWpErrorWithCode($result, 'setup_expired');
    }

    private function raisePasskeyChallenge($method)
    {
        $method->prepareChallenge($this->admin);

        return random_bytes(32);
    }

    private function rowWithChallenge($challenge)
    {
        return (object)[
            EnrollmentTwoFaMethod::CHALLENGE_COLUMN => Base64Url::encode($challenge)
        ];
    }

    /* ----------------------------------------------------------- the migration */

    /**
     * A role named as required but absent from the allow list used to be a policy that
     * did nothing at all. It starts working with this change - which is what the owner
     * asked for, but not today and without warning, so the list is narrowed once to what
     * was genuinely in force.
     */
    public function test_the_migration_drops_a_requirement_that_was_never_in_force()
    {
        $this->writeRaw([
            'totp_2fa'            => 'yes',
            'totp_2fa_roles'      => ['editor'],
            'totp_required_roles' => ['administrator', 'editor']
        ]);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame(['editor'], Helper::getSetting('totp_required_roles'));
    }

    public function test_the_migration_empties_a_requirement_held_while_the_method_was_off()
    {
        $this->writeRaw([
            'totp_2fa'            => 'no',
            'totp_2fa_roles'      => ['administrator'],
            'totp_required_roles' => ['administrator']
        ]);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame([], Helper::getSetting('totp_required_roles'));
    }

    public function test_the_migration_leaves_a_requirement_that_was_already_working()
    {
        $this->writeRaw([
            'totp_2fa'            => 'yes',
            'totp_2fa_roles'      => ['administrator'],
            'totp_required_roles' => ['administrator']
        ]);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame(['administrator'], Helper::getSetting('totp_required_roles'));
    }

    /**
     * It has to be idempotent: the hook it rides fires on every admin page load, and a
     * second pass over a list the owner has since widened would quietly narrow it again.
     */
    public function test_the_migration_runs_once_and_leaves_later_choices_alone()
    {
        $this->writeRaw([
            'totp_2fa'            => 'yes',
            'totp_2fa_roles'      => ['editor'],
            'totp_required_roles' => ['administrator']
        ]);

        Activator::maybeMigrateSettings();

        // The owner now deliberately requires a role the allow list does not name.
        $settings = get_option('__fls_auth_settings');
        $settings['totp_required_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame(['administrator'], Helper::getSetting('totp_required_roles'));
    }

    private function writeRaw($overrides)
    {
        $settings = array_merge(Helper::getAuthSettings(), $overrides);
        update_option('__fls_auth_settings', $settings);
        delete_option('__fls_required_roles_migrated');
        delete_option('__fls_required_methods_migrated');
        Helper::resetStatics();
    }

    /* ------------------------------ keeping a 3.0.0 requirement enforcing on update */

    /**
     * The state 3.0.0 documented as fully enforcing: roles required, every switch off.
     * Under the new rule that is a requirement over nothing, so the update has to switch
     * the app on rather than let the policy evaporate in silence.
     */
    public function test_the_update_keeps_a_requirement_that_had_no_method_switched_on()
    {
        $this->writeRaw([
            'totp_2fa'            => 'no',
            'passkey_2fa'         => 'no',
            'email2fa'            => 'no',
            'totp_2fa_roles'      => [],
            'totp_required_roles' => ['administrator']
        ]);
        // The 3.0.0 population already carries the first migration's flag.
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('yes', Helper::getSetting('totp_2fa'), 'the app is switched on to preserve the policy');
        $this->assertSame([], Helper::getSetting('totp_2fa_roles'), 'and reaches the required roles through the grant, nobody else');
        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
        $this->assertFalse(TotpTwoFaMethod::isAllowedForUser($this->subscriber));
    }

    /**
     * Half covered is not covered. Enforcement is per user, so a site requiring two roles
     * while emailed codes reach only one of them would have kept the covered role and
     * quietly dropped the other.
     */
    public function test_the_update_covers_every_required_role_not_just_one_of_them()
    {
        $this->writeRaw([
            'totp_2fa'              => 'no',
            'passkey_2fa'           => 'no',
            'email2fa'              => 'yes',
            'email2fa_roles'        => ['administrator'],
            'two_fa_required_level' => DeviceRequirement::LEVEL_ANY,
            'totp_required_roles'   => ['administrator', 'editor']
        ]);
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('yes', Helper::getSetting('totp_2fa'), 'the editor had nothing, so the app is switched on');

        $editor = $this->factory->user->create_and_get(['role' => 'editor']);
        $this->assertTrue(DeviceRequirement::isRequiredForUser($editor));
    }

    /**
     * A passkey switch stored as on means nothing over plain http - the ceremony cannot
     * run - so it must not be read as a live method by the migration either.
     */
    public function test_the_update_does_not_count_passkeys_on_a_site_without_https()
    {
        update_option('home', 'http://example.org');
        update_option('siteurl', 'http://example.org');

        $this->writeRaw([
            'totp_2fa'            => 'no',
            'passkey_2fa'         => 'yes',
            'email2fa'            => 'no',
            'totp_required_roles' => ['administrator']
        ]);
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('yes', Helper::getSetting('totp_2fa'), 'nothing else could hold the requirement up');
        $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
    }

    /**
     * Site code can veto a method for one person. With that method the only one on, the
     * requirement has nothing left to stand on for them.
     */
    public function test_a_vetoed_method_cannot_hold_a_requirement_up()
    {
        $this->policy([], ['administrator'], 'yes');   // app on, and the only method

        $this->assertTrue(DeviceRequirement::canBeSatisfiedBy($this->admin));

        add_filter('fluent_auth/totp_enabled', '__return_false');

        try {
            $this->assertFalse(
                DeviceRequirement::canBeSatisfiedBy($this->admin),
                'the one method they could have used has been taken away from them'
            );
            $this->assertFalse(DeviceRequirement::isRequiredForUser($this->admin));
        } finally {
            remove_filter('fluent_auth/totp_enabled', '__return_false');
        }
    }

    /**
     * A veto filter that asks whether the user is required would call back into the
     * question being answered. Left open that is a stack overflow on their next login.
     */
    public function test_a_veto_filter_that_asks_about_the_requirement_does_not_recurse()
    {
        $this->policy([], ['administrator'], 'yes');

        $reentrant = function ($enabled, $user) {
            // The shape that recurses: "the app is for people who must hold one".
            return DeviceRequirement::isRequiredForUser($user);
        };

        add_filter('fluent_auth/totp_enabled', $reentrant, 10, 2);

        try {
            $this->assertTrue(DeviceRequirement::canBeSatisfiedBy($this->admin));
            $this->assertTrue(DeviceRequirement::isRequiredForUser($this->admin));
        } finally {
            remove_filter('fluent_auth/totp_enabled', $reentrant, 10);
        }
    }

    /** The positive side of the https rule: passkeys over https hold it up on their own. */
    public function test_the_update_leaves_a_passkey_only_site_on_https_alone()
    {
        $this->enablePasskeys(['administrator']);   // sets home/siteurl to https

        $this->writeRaw([
            'totp_2fa'            => 'no',
            'passkey_2fa'         => 'yes',
            'email2fa'            => 'no',
            'totp_required_roles' => ['administrator']
        ]);
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('no', Helper::getSetting('totp_2fa'), 'passkeys already hold the requirement up');
    }

    /** A site that already had a method on is left exactly alone. */
    public function test_the_update_leaves_a_working_requirement_alone()
    {
        $this->writeRaw([
            'totp_2fa'            => 'no',
            'passkey_2fa'         => 'no',
            'email2fa'            => 'yes',
            'email2fa_roles'      => ['administrator'],
            'two_fa_required_level' => DeviceRequirement::LEVEL_ANY,
            'totp_required_roles' => ['administrator']
        ]);
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('no', Helper::getSetting('totp_2fa'), 'nothing to preserve, so nothing is touched');
    }

    /** No requirement, nothing to preserve. */
    public function test_the_update_touches_nothing_where_no_role_is_required()
    {
        $this->writeRaw([
            'totp_2fa'            => 'no',
            'totp_required_roles' => []
        ]);
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('no', Helper::getSetting('totp_2fa'));
    }

    /** It rides an every-page-load hook, so a second pass must change nothing. */
    public function test_the_update_is_idempotent()
    {
        $this->writeRaw([
            'totp_2fa'            => 'no',
            'passkey_2fa'         => 'no',
            'email2fa'            => 'no',
            'totp_required_roles' => ['administrator']
        ]);
        update_option('__fls_required_roles_migrated', 'yes', true);

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        // The owner then deliberately switches it back off.
        $settings = Helper::getAuthSettings();
        $settings['totp_2fa'] = 'no';
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        Activator::maybeMigrateSettings();
        Helper::resetStatics();

        $this->assertSame('no', Helper::getSetting('totp_2fa'), 'a decision made after the migration stands');
    }

    /* ------------------------------------------------------- the strength floor */

    public function test_the_floor_defaults_to_a_device_factor()
    {
        $this->assertSame(DeviceRequirement::LEVEL_DEVICE, DeviceRequirement::getLevel());
    }

    /**
     * The whole point of the default. An emailed code proves the mailbox, which is also
     * where password resets arrive - so at the strong floor it cannot stand in for the
     * device the policy asked for.
     */
    public function test_an_emailed_code_does_not_meet_a_device_floor()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enableEmail2Fa();

        $this->assertFalse(DeviceRequirement::isSatisfiedBy($this->admin));
        $this->assertTrue(DeviceRequirement::isOwedBy($this->admin));
    }

    public function test_an_emailed_code_meets_the_relaxed_floor()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enableEmail2Fa();
        $this->setLevel(DeviceRequirement::LEVEL_ANY);

        $this->assertTrue(DeviceRequirement::isSatisfiedBy($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    /**
     * The floor says what *counts*; it does not switch a method on. Reading it the other
     * way round made the whole requirement circular: email was granted to every required
     * user, the grant satisfied the requirement, and nobody at that level was ever asked
     * for anything - including the people already signed in that the backstop exists for.
     */
    public function test_the_relaxed_floor_does_not_switch_email_codes_on()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->setLevel(DeviceRequirement::LEVEL_ANY);

        $this->assertFalse(
            (new EmailTwoFaMethod())->isAvailableForUser($this->admin),
            'A floor that enables the thing it accepts can never be unmet.'
        );
    }

    public function test_the_relaxed_floor_still_owes_a_factor_where_email_is_not_configured()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->setLevel(DeviceRequirement::LEVEL_ANY);

        $this->assertFalse(DeviceRequirement::isSatisfiedBy($this->admin));
        $this->assertTrue(
            DeviceRequirement::isOwedBy($this->admin),
            'Relaxing the floor must not excuse an account that holds nothing at all.'
        );
        $this->assertInstanceOf(
            EnrollmentTwoFaMethod::class,
            TwoFaService::getRequiredMethod($this->admin, [])
        );
    }

    /**
     * The floor is a statement about required roles. Reading it anywhere else let it
     * reach people it was never about - flipping it to `any` silently stopped every
     * ordinary user with email codes being offered an authenticator app.
     */
    public function test_the_floor_does_not_leak_into_the_nudge()
    {
        $this->policy(['administrator'], []);
        $this->enableEmail2Fa();
        $this->setLevel(DeviceRequirement::LEVEL_ANY);

        $this->assertTrue(
            (new TotpNudgeHandler())->shouldAsk($this->admin),
            'An emailed code is not the device the nudge is offering.'
        );
    }

    public function test_a_device_factor_still_silences_the_nudge_at_the_relaxed_floor()
    {
        $this->policy(['administrator'], []);
        $this->setLevel(DeviceRequirement::LEVEL_ANY);
        $this->enrolTotp($this->admin);

        $this->assertFalse((new TotpNudgeHandler())->shouldAsk($this->admin));
    }

    public function test_the_relaxed_floor_changes_nothing_for_roles_that_are_not_required()
    {
        $this->policy(['administrator'], []);
        $this->setLevel(DeviceRequirement::LEVEL_ANY);

        $this->assertFalse((new EmailTwoFaMethod())->isAvailableForUser($this->admin));
    }

    /**
     * Even at the relaxed floor the ordering holds, so a user who has a device factor is
     * asked for that rather than being dropped to the weakest thing on the list.
     */
    public function test_a_device_factor_still_outranks_email_at_the_relaxed_floor()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enableEmail2Fa();
        $this->setLevel(DeviceRequirement::LEVEL_ANY);
        $this->enrolTotp($this->admin);

        $this->assertInstanceOf(
            TotpTwoFaMethod::class,
            TwoFaService::getRequiredMethod($this->admin, [])
        );
    }

    public function test_an_authenticator_app_satisfies_it()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enrolTotp($this->admin);

        $this->assertTrue(DeviceRequirement::isSatisfiedBy($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    /**
     * The bug the old rule had: it asked whether the user had an authenticator app, so
     * somebody holding the stronger factor was marched off to set up the weaker one.
     */
    public function test_a_passkey_satisfies_it_without_an_authenticator_app()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $this->addPasskey($this->admin, 'cred-one');
        $this->addPasskey($this->admin, 'cred-two');

        $this->assertTrue(DeviceRequirement::isSatisfiedBy($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    /**
     * "Available", not merely "enrolled", and the difference decides a real case.
     * PasskeyTwoFaMethod refuses to be the only thing in front of an account, so a lone
     * passkey with nothing to fall back on is never asked for. Counting it as satisfied
     * would let exactly the user this policy is about sign in on a password alone.
     */
    public function test_a_lone_passkey_with_no_fallback_does_not_satisfy_it()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $this->addPasskey($this->admin, 'cred-only');

        $this->assertFalse(
            DeviceRequirement::isSatisfiedBy($this->admin),
            'A credential that will never be challenged is not a second factor.'
        );
        $this->assertTrue(DeviceRequirement::isOwedBy($this->admin));
    }

    public function test_recovery_codes_make_a_lone_passkey_count()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enablePasskeys();

        $this->addPasskey($this->admin, 'cred-only');
        RecoveryCodes::generate($this->admin);

        $this->assertTrue(DeviceRequirement::isSatisfiedBy($this->admin));
    }

    public function test_the_requirement_can_be_waived_by_filter()
    {
        $this->policy(['administrator'], ['administrator']);

        add_filter('fluent_auth/device_factor_required', '__return_false');

        $this->assertFalse(DeviceRequirement::isRequiredForUser($this->admin));
    }

    /* --------------------------------------------------- the dispatcher answers */

    /**
     * The hole, stated directly. getRequiredMethod() used to return null here - no
     * method was *available*, because none was enrolled - and a null means the login
     * proceeds and the cookie is issued.
     */
    public function test_the_dispatcher_now_answers_for_a_required_unenrolled_user()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = TwoFaService::getRequiredMethod($this->admin, []);

        $this->assertInstanceOf(EnrollmentTwoFaMethod::class, $method);
    }

    public function test_an_enrolled_user_is_challenged_rather_than_asked_to_enrol()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enrolTotp($this->admin);

        $method = TwoFaService::getRequiredMethod($this->admin, []);

        $this->assertInstanceOf(TotpTwoFaMethod::class, $method);
    }

    public function test_a_user_outside_the_required_roles_is_asked_for_nothing()
    {
        $this->policy(['administrator'], ['administrator']);

        $this->assertNull(TwoFaService::getRequiredMethod($this->subscriber, []));
    }

    /**
     * The ordering is the policy. A mailed code proves the mailbox, which is not what a
     * device requirement asks for - if email won here, every user under the rule would
     * satisfy it by doing nothing, and the rule would mean nothing.
     */
    public function test_enrolment_outranks_an_emailed_code()
    {
        $this->policy(['administrator'], ['administrator']);

        $settings = Helper::getAuthSettings();
        $settings['email2fa'] = 'yes';
        $settings['email2fa_roles'] = ['administrator'];
        update_option('__fls_auth_settings', $settings);
        Helper::resetStatics();

        $method = TwoFaService::getRequiredMethod($this->admin, []);

        $this->assertInstanceOf(EnrollmentTwoFaMethod::class, $method);
        $this->assertNotInstanceOf(EmailTwoFaMethod::class, $method);
    }

    /* ------------------------------------------------------- before the cookie */

    /**
     * The point of the whole change: the password was right and the cookie is still
     * not sent.
     */
    public function test_the_auth_cookie_is_withheld_from_a_user_who_owes_a_factor()
    {
        $this->policy(['administrator'], ['administrator']);

        $handler = new TwoFaHandler();

        $this->assertFalse(
            $handler->maybeWithholdAuthCookies(true, 0, 0, $this->admin->ID),
            'A user who owes a device factor must not be handed a session.'
        );
        $this->assertTrue(TwoFaHandler::hasWithheldCookiesFor($this->admin->ID));
    }

    public function test_the_auth_cookie_is_sent_once_the_factor_is_held()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enrolTotp($this->admin);
        Helper::setSatisfiedFactors(['device']);

        $handler = new TwoFaHandler();

        $this->assertTrue($handler->maybeWithholdAuthCookies(true, 0, 0, $this->admin->ID));
    }

    /**
     * The other door into the same building. A REST or XML-RPC login has nowhere to put
     * a challenge form, so TwoFaHandler refuses the login outright and hands back the
     * URL to finish at - and that refusal has to cover somebody who owes enrollment
     * just as it covers somebody who owes a code.
     *
     * This is also the whole of the XML-RPC story, and why TotpEnforcementHandler has no
     * `xmlrpc_enabled` filter: that filter is applied from wp_xmlrpc_server::__construct()
     * before any authentication happens, and XML-RPC carries a username and password
     * rather than a cookie - so there is never a pre-existing session there for a
     * backstop to catch, only a login, which is refused here.
     *
     * Driven through wp_doing_ajax() rather than by define()ing XMLRPC_REQUEST, because a
     * constant defined in one test is defined for every test that follows it in the
     * process - which silently turns every later "is this a background request" check the
     * wrong way round.
     */
    public function test_a_headless_login_is_refused_for_a_user_who_owes_a_factor()
    {
        $this->policy(['administrator'], ['administrator']);

        add_filter('wp_doing_ajax', '__return_true');

        $result = (new TwoFaHandler())->maybeDenyHeadlessLogin($this->admin);

        remove_filter('wp_doing_ajax', '__return_true');

        $this->assertWpErrorWithCode($result, 'fls_2fa_required');
    }

    public function test_the_pending_row_records_the_enrolment_step()
    {
        $this->policy(['administrator'], ['administrator']);

        $raised = (new TwoFaHandler())->sendAndGet2FaConfirmFormUrl($this->admin, 'both');

        $this->assertNotFalse($raised);

        $row = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $raised['login_hash'])
            ->first();

        $this->assertNotNull($row);
        $this->assertSame(EnrollmentTwoFaMethod::KEY, $row->use_type);
        $this->assertEquals($this->admin->ID, $row->user_id);
        $this->assertSame('issued', $row->status);
    }

    /**
     * The form is drawn from the pending row, because on this screen there is no session
     * and the hash is the only credential it has.
     */
    public function test_the_enrolment_form_renders_a_setup_key_for_the_row_it_is_given()
    {
        $this->policy(['administrator'], ['administrator']);

        $raised = (new TwoFaHandler())->sendAndGet2FaConfirmFormUrl($this->admin, 'both');

        $html = (new EnrollmentTwoFaMethod())->renderForm(['login_hash' => $raised['login_hash']]);

        $this->assertStringContainsString('fls_enroll_code', $html);
        $this->assertStringContainsString($raised['login_hash'], $html);
        $this->assertStringContainsString('Setup key', $html);
    }

    public function test_the_enrolment_form_gives_nothing_away_for_an_unknown_hash()
    {
        $this->policy(['administrator'], ['administrator']);

        $html = (new EnrollmentTwoFaMethod())->renderForm(['login_hash' => 'not-a-real-hash']);

        $this->assertStringNotContainsString('Setup key', $html);
        $this->assertStringNotContainsString('fls_enroll_code', $html);
    }

    /* ------------------------------------------------------------- enrolment */

    public function test_a_wrong_code_does_not_enrol_and_counts_as_a_guess()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);

        $result = $method->verifyProof($this->admin, (object)[], ['fls_enroll_code' => '000000']);

        $this->assertFalse($result, 'A wrong code is a guess, not a hard error.');
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->admin));
    }

    public function test_an_empty_code_does_not_enrol()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);

        $this->assertWpErrorWithCode($method->verifyProof($this->admin, (object)[], []), 'invalid_code');
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->admin));
    }

    public function test_the_right_code_enrols_and_clears_the_requirement()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);

        $secret = TotpTwoFaMethod::getPendingSecret($this->admin->ID);
        $code = $this->currentCode($secret);

        $this->assertTrue($method->verifyProof($this->admin, (object)[], ['fls_enroll_code' => $code]));
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($this->admin));
        $this->assertFalse(DeviceRequirement::isOwedBy($this->admin));
    }

    /**
     * Recovery codes are shown once or never. Minting a set nobody sees is worse than
     * minting none, because the account then looks recoverable and is not.
     */
    public function test_enrolment_hands_over_recovery_codes_before_redirecting()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);

        $secret = TotpTwoFaMethod::getPendingSecret($this->admin->ID);
        $method->verifyProof($this->admin, (object)[], ['fls_enroll_code' => $this->currentCode($secret)]);

        $response = $method->getSuccessResponse(['redirect' => 'https://example.org/'], $this->admin, (object)[]);

        $this->assertArrayHasKey('recovery_codes', $response);
        $this->assertNotEmpty($response['recovery_codes']);
        $this->assertSame('https://example.org/', $response['redirect']);
        $this->assertSame(count($response['recovery_codes']), RecoveryCodes::countRemaining($this->admin));
    }

    /**
     * Someone who enrolled in another tab owes nothing any more, and activating a
     * second secret over the one they just paired would break the app they are holding.
     */
    public function test_enrolment_refuses_once_the_requirement_is_already_met()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);
        $secret = TotpTwoFaMethod::getPendingSecret($this->admin->ID);

        $this->enrolTotp($this->admin);

        $result = $method->verifyProof($this->admin, (object)[], ['fls_enroll_code' => $this->currentCode($secret)]);

        $this->assertWpErrorWithCode($result, 'already_enrolled');
    }

    /**
     * The setup screen is now reachable by anyone who knows the password, before any
     * cookie exists - so the secret it shows must not outlive the attempt that raised
     * it. Otherwise somebody who has the password signs in, reads the setup key, walks
     * away, and the real account holder is later handed the same key, scans it and
     * activates it: both hold the authenticator, and the site calls the account
     * protected.
     */
    public function test_each_login_attempt_gets_its_own_setup_secret()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();

        $method->prepareChallenge($this->admin);
        $readByTheFirstAttempt = TotpTwoFaMethod::getPendingSecret($this->admin->ID);

        $method->prepareChallenge($this->admin);
        $shownToTheSecond = TotpTwoFaMethod::getPendingSecret($this->admin->ID);

        $this->assertNotEmpty($readByTheFirstAttempt);
        $this->assertNotSame(
            $readByTheFirstAttempt,
            $shownToTheSecond,
            'A pending secret has no expiry, so reusing it hands one attempt the other one\'s factor.'
        );
    }

    public function test_a_secret_read_from_an_abandoned_attempt_cannot_be_activated()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();

        $method->prepareChallenge($this->admin);
        $stale = TotpTwoFaMethod::getPendingSecret($this->admin->ID);

        // The real account holder starts their own attempt.
        $method->prepareChallenge($this->admin);

        $result = $method->verifyProof(
            $this->admin,
            (object)[],
            ['fls_enroll_code' => $this->currentCode($stale)]
        );

        $this->assertFalse($result);
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($this->admin));
    }

    /**
     * Malformed input, not a wrong guess - so it must not spend one of the five
     * attempts. This is the only route to a session now, so burning the row on an
     * autofocused empty field is a dead end rather than a nuisance.
     */
    public function test_an_empty_code_is_a_hard_error_rather_than_a_spent_attempt()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);

        $result = $method->verifyProof($this->admin, (object)[], ['fls_enroll_code' => '']);

        $this->assertWpErrorWithCode($result, 'invalid_code');
    }

    /**
     * wp_signon() can still be vetoed after the proof is accepted - by another plugin on
     * `authenticate`, or by core's multisite checks. Codes minted before that point are
     * codes nobody is ever shown, while RecoveryCodes::hasAny() goes on reporting the
     * account as having a set that can never be regenerated.
     */
    public function test_recovery_codes_are_not_minted_until_the_sign_in_has_happened()
    {
        $this->policy(['administrator'], ['administrator']);

        $method = new EnrollmentTwoFaMethod();
        $method->prepareChallenge($this->admin);
        $secret = TotpTwoFaMethod::getPendingSecret($this->admin->ID);

        $method->verifyProof($this->admin, (object)[], ['fls_enroll_code' => $this->currentCode($secret)]);

        $this->assertSame(
            0,
            RecoveryCodes::countRemaining($this->admin),
            'Proving the factor is not the same as completing the login.'
        );

        $method->getSuccessResponse(['redirect' => '/'], $this->admin, (object)[]);

        $this->assertGreaterThan(0, RecoveryCodes::countRemaining($this->admin));
    }

    /* ----------------------------------------------------- the legacy backstop */

    /**
     * The surface the old gate left wide open: a cookie issued before the policy
     * existed still authenticated every REST call on the site.
     */
    public function test_rest_is_refused_for_a_session_that_owes_a_factor()
    {
        $this->policy(['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $result = (new TotpEnforcementHandler())->maybeDenyRest(null);

        $this->assertWpErrorWithCode($result, 'fls_2fa_enrollment_required');
        $this->assertSame(403, $result->get_error_data()['status']);
    }

    public function test_rest_is_left_alone_for_a_session_that_owes_nothing()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enrolTotp($this->admin);
        wp_set_current_user($this->admin->ID);

        $this->assertNull((new TotpEnforcementHandler())->maybeDenyRest(null));
    }

    public function test_rest_is_left_alone_for_anonymous_requests()
    {
        $this->policy(['administrator'], ['administrator']);
        wp_set_current_user(0);

        $this->assertNull((new TotpEnforcementHandler())->maybeDenyRest(null));
    }

    /**
     * Somebody else's refusal is somebody else's to explain.
     */
    public function test_an_existing_rest_error_is_not_replaced()
    {
        $this->policy(['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $existing = new \WP_Error('someone_else', 'Nope');

        $this->assertSame($existing, (new TotpEnforcementHandler())->maybeDenyRest($existing));
    }

    /**
     * Core's rest_cookie_check_errors() runs at 100 and treats a REST request carrying a
     * login cookie but no nonce as anonymous - it zeroes the current user and returns
     * true. Running ahead of that would 403 ordinary nonce-less fetches against public
     * endpoints for this user and nobody else, so the filter sits at 101 and this is the
     * shape it must have by then.
     */
    public function test_rest_is_left_alone_once_core_has_ruled_the_request_anonymous()
    {
        $this->policy(['administrator'], ['administrator']);
        wp_set_current_user(0);

        $this->assertTrue(
            (new TotpEnforcementHandler())->maybeDenyRest(true),
            "Core's own decision must survive."
        );
    }

    public function test_the_rest_filter_runs_after_core_decides_who_is_signed_in()
    {
        $handler = new TotpEnforcementHandler();
        $handler->register();

        $this->assertGreaterThan(
            100,
            has_filter('rest_authentication_errors', [$handler, 'maybeDenyRest']),
            'Ahead of core at 100 this refuses requests core would serve anonymously.'
        );
    }

    /* ----------------------------------------------------------- admin-ajax */

    public function test_admin_ajax_is_refused_for_a_session_that_owes_a_factor()
    {
        $this->policy(['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $_REQUEST['action'] = 'some_other_plugin_action';

        $this->assertSame(403, $this->captureAjaxDenial());
    }

    /**
     * Registering a passkey is one of the two ways to satisfy the very requirement being
     * enforced, and it runs entirely over ajax. Closing it would tell a user to set up a
     * second factor and then refuse them the means.
     */
    public function test_passkey_registration_stays_open_to_somebody_who_owes_a_factor()
    {
        $this->policy(['administrator'], ['administrator']);
        wp_set_current_user($this->admin->ID);

        $_REQUEST['action'] = 'fluent_auth_passkey_register';

        $this->assertNull($this->captureAjaxDenial());
    }

    public function test_admin_ajax_is_left_alone_for_a_session_that_owes_nothing()
    {
        $this->policy(['administrator'], ['administrator']);
        $this->enrolTotp($this->admin);
        wp_set_current_user($this->admin->ID);

        $_REQUEST['action'] = 'some_other_plugin_action';

        $this->assertNull($this->captureAjaxDenial());
    }

    /**
     * @return int|null the status wp_send_json emitted, or null if nothing was refused
     */
    private function captureAjaxDenial()
    {
        $status = null;

        $catch = function ($response, $statusCode) use (&$status) {
            $status = $statusCode;
            throw new \RuntimeException('denied');
        };

        add_filter('wp_doing_ajax', '__return_true');
        add_filter('fluent_auth_test_json', $catch, 10, 2);
        add_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        ob_start();
        try {
            (new TotpEnforcementHandler())->maybeDenyAjax();
        } catch (\WPDieException $e) {
            $status = 403;
        } catch (\RuntimeException $e) {
            // not reached; kept so a future change to the denial shape is visible
        }
        ob_end_clean();

        remove_filter('wp_doing_ajax', '__return_true');
        remove_filter('fluent_auth_test_json', $catch, 10);
        remove_filter('wp_die_ajax_handler', [$this, 'throwingDieHandler']);

        unset($_REQUEST['action']);

        return $status;
    }

    public function throwingDieHandler()
    {
        return function ($message = '') {
            throw new \WPDieException((string)$message);
        };
    }

    /* ------------------------------------------------------------- the nudge */

    public function test_a_passkey_user_is_not_nagged_to_add_an_authenticator_app()
    {
        $this->policy(['administrator'], []);
        $this->enablePasskeys();

        $this->addPasskey($this->admin, 'cred-one');
        $this->addPasskey($this->admin, 'cred-two');

        $this->assertFalse(
            (new TotpNudgeHandler())->shouldAsk($this->admin),
            'They hold the thing an authenticator app would prove.'
        );
    }

    public function test_a_user_with_nothing_is_still_nagged()
    {
        $this->policy(['administrator'], []);

        $this->assertTrue((new TotpNudgeHandler())->shouldAsk($this->admin));
    }
}
