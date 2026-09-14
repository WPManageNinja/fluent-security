<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Onboarding;
use FluentAuth\App\Services\SecurityChecks;

/**
 * The setup wizard.
 *
 * Two things are being protected here. The obvious one is that answers turn into the right
 * settings. The one worth writing tests for is everything the wizard is not allowed to do:
 * write more than once, require a second factor, be completed twice, or accept a value no
 * screen offered.
 */
class OnboardingTest extends BaseTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        delete_option(Onboarding::OPTION);

        update_option('__fls_auth_settings', [
            'disable_xmlrpc'          => 'no',
            'disable_users_rest'      => 'no',
            'secure_signup_form'      => 'no',
            'login_try_limit'         => 5,
            'login_try_timing'        => 30,
            'notification_user_roles' => [],
            'notification_email'      => '{admin_email}',
            'totp_2fa'                => 'no',
            'totp_2fa_roles'          => [],
            'totp_required_roles'     => [],
            'email2fa'                => 'no',
            'email2fa_roles'          => [],
            'trusted_proxies'         => '',
            'proxy_ip_header'         => ''
        ]);

        Helper::resetStatics();
    }

    /**
     * Puts this request behind an undeclared proxy.
     *
     * The connection step is only offered where a relay is plausible - a site with
     * nothing in front of it is not asked about reverse proxies at all - so a test of
     * what the step does has to put the site in a state where it is asked.
     */
    private function behindAnUndeclaredProxy()
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';

        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        delete_option(Onboarding::OPTION);
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR']);

        parent::tearDown();
    }

    /* --------------------------------------------------------------- the flag */

    public function test_a_fresh_site_has_not_been_onboarded()
    {
        $this->assertFalse(Onboarding::isDone());
        $this->assertSame('', Onboarding::state());
    }

    public function test_skipping_closes_the_wizard_without_writing_a_setting()
    {
        $before = get_option('__fls_auth_settings');

        Onboarding::skip();

        $this->assertTrue(Onboarding::isDone());
        $this->assertSame('skipped', Onboarding::state());
        $this->assertSame($before, get_option('__fls_auth_settings'));
    }

    public function test_completing_stamps_a_date_rather_than_a_boolean()
    {
        Onboarding::complete([]);

        $this->assertNotSame('skipped', Onboarding::state());
        $this->assertNotFalse(strtotime(Onboarding::state()));
    }

    public function test_setup_cannot_be_completed_twice()
    {
        Onboarding::complete([]);

        $this->assertWpErrorWithCode(Onboarding::complete([]), 'already_onboarded');
    }

    /* ------------------------------------------------------------- the answers */

    public function test_two_factor_answers_turn_on_the_chosen_methods_for_the_chosen_roles()
    {
        Onboarding::complete([
            'two_fa' => [
                'totp'  => true,
                'email' => true,
                'roles' => ['administrator', 'editor']
            ]
        ]);

        $this->assertSame('yes', Helper::getSetting('totp_2fa'));
        $this->assertSame('yes', Helper::getSetting('email2fa'));
        $this->assertSame(['administrator', 'editor'], Helper::getSetting('totp_2fa_roles'));
        $this->assertSame(['administrator', 'editor'], Helper::getSetting('email2fa_roles'));
    }

    /**
     * The rule the whole screen is built around. Offering a second factor is safe on any
     * site; requiring one from a wizard, before a single person has enrolled, locks the
     * administrator out of the site they installed this on ten minutes ago.
     */
    public function test_setup_never_writes_required_two_factor_roles()
    {
        Onboarding::complete([
            'two_fa' => [
                'totp'  => true,
                'email' => true,
                'roles' => ['administrator', 'editor', 'author']
            ]
        ]);

        $this->assertSame([], Helper::getSetting('totp_required_roles'));
    }

    public function test_a_method_with_no_roles_is_refused()
    {
        $error = Onboarding::complete([
            'two_fa' => ['totp' => true, 'email' => false, 'roles' => []]
        ]);

        $this->assertWpErrorWithCode($error, 'roles_required');
    }

    /** A role this site does not have is dropped rather than written through. */
    public function test_unknown_roles_are_discarded()
    {
        Onboarding::complete([
            'two_fa' => [
                'totp'  => true,
                'email' => false,
                'roles' => ['administrator', 'wp_god_mode']
            ]
        ]);

        $this->assertSame(['administrator'], Helper::getSetting('totp_2fa_roles'));
    }

    public function test_turning_two_factor_off_is_a_valid_answer()
    {
        Onboarding::complete([
            'two_fa' => ['totp' => false, 'email' => false, 'roles' => []]
        ]);

        $this->assertSame('no', Helper::getSetting('totp_2fa'));
        $this->assertSame('no', Helper::getSetting('email2fa'));
    }

    public function test_the_attempt_limit_is_written()
    {
        Onboarding::complete([
            'login_limit' => ['limit' => 3, 'timing' => 60]
        ]);

        $this->assertSame(3, Helper::getSetting('login_try_limit'));
        $this->assertSame(60, Helper::getSetting('login_try_timing'));
    }

    /**
     * @dataProvider impossibleLimits
     */
    public function test_an_impossible_attempt_limit_is_refused($limit, $timing)
    {
        $error = Onboarding::complete([
            'login_limit' => ['limit' => $limit, 'timing' => $timing]
        ]);

        $this->assertWpErrorWithCode($error, 'invalid_limit');
    }

    public function impossibleLimits()
    {
        return [
            'no attempts allowed'  => [0, 30],
            'negative attempts'    => [-5, 30],
            'absurd attempts'      => [5000, 30],
            'no window'            => [5, 0],
            'a window over a day'  => [5, 10000]
        ];
    }

    public function test_the_hardening_screen_writes_all_three_of_its_answers()
    {
        Onboarding::complete([
            'hardening' => [
                'disable_xmlrpc'     => true,
                'disable_users_rest' => true,
                'secure_signup_form' => false
            ]
        ]);

        $this->assertSame('yes', Helper::getSetting('disable_xmlrpc'));
        $this->assertSame('yes', Helper::getSetting('disable_users_rest'));
        $this->assertSame('no', Helper::getSetting('secure_signup_form'));
    }

    public function test_alerts_are_written_with_the_chosen_roles_and_address()
    {
        Onboarding::complete([
            'alerts' => [
                'enabled' => true,
                'roles'   => ['administrator'],
                'email'   => 'security@example.com'
            ]
        ]);

        $this->assertSame(['administrator'], Helper::getSetting('notification_user_roles'));
        $this->assertSame('security@example.com', Helper::getSetting('notification_email'));
    }

    /** The shipped default is a token that resolves at send time, not an address. */
    public function test_the_admin_email_token_is_accepted_as_an_address()
    {
        $result = Onboarding::complete([
            'alerts' => [
                'enabled' => true,
                'roles'   => ['administrator'],
                'email'   => '{admin_email}'
            ]
        ]);

        $this->assertNotWPError($result);
        $this->assertSame('{admin_email}', Helper::getSetting('notification_email'));
    }

    public function test_a_malformed_alert_address_is_refused()
    {
        $error = Onboarding::complete([
            'alerts' => [
                'enabled' => true,
                'roles'   => ['administrator'],
                'email'   => 'not-an-address'
            ]
        ]);

        $this->assertWpErrorWithCode($error, 'invalid_email');
    }

    public function test_turning_alerts_off_empties_the_roles()
    {
        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['notification_user_roles' => ['administrator']]
        ));
        Helper::resetStatics();

        Onboarding::complete([
            'alerts' => ['enabled' => false]
        ]);

        $this->assertSame([], Helper::getSetting('notification_user_roles'));
    }

    /* ---------------------------------------------------------- the connection */

    public function test_declaring_a_proxy_writes_it()
    {
        $this->behindAnUndeclaredProxy();

        Onboarding::complete([
            'connection' => [
                'mode'            => 'proxy',
                'trusted_proxies' => '10.0.0.1, 192.168.1.0/24',
                'proxy_ip_header' => 'X-Forwarded-For'
            ]
        ]);

        $this->assertSame('10.0.0.1,192.168.1.0/24', Helper::getSetting('trusted_proxies'));
        $this->assertSame('X-Forwarded-For', Helper::getSetting('proxy_ip_header'));
    }

    public function test_a_proxy_answer_with_nothing_to_trust_is_refused()
    {
        $this->behindAnUndeclaredProxy();

        $error = Onboarding::complete([
            'connection' => ['mode' => 'proxy', 'trusted_proxies' => '']
        ]);

        $this->assertWpErrorWithCode($error, 'proxy_required');
    }

    /** Anything that is not an address or a range is dropped before it is written. */
    public function test_junk_in_the_proxy_list_is_discarded()
    {
        $this->behindAnUndeclaredProxy();

        $error = Onboarding::complete([
            'connection' => [
                'mode'            => 'proxy',
                'trusted_proxies' => 'not-an-ip, evil.example.com'
            ]
        ]);

        $this->assertWpErrorWithCode($error, 'proxy_required');
    }

    /**
     * Saying the resolved address is your own is an answer, and the right thing to do with
     * it is nothing. It must never be read as an instruction to undo a declared proxy - see
     * the note on the connection step.
     */
    public function test_answering_direct_leaves_a_declared_proxy_alone()
    {
        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['trusted_proxies' => '10.0.0.1']
        ));
        Helper::resetStatics();

        Onboarding::complete(['connection' => ['mode' => 'direct']]);

        $this->assertSame('10.0.0.1', Helper::getSetting('trusted_proxies'));
    }

    /* ------------------------------------------------------------- the writing */

    /**
     * Saving replaces the whole option, so a wizard that wrote per screen would give five
     * chances to leave a site half configured behind a closed browser.
     */
    public function test_every_answer_is_applied_in_a_single_write()
    {
        $writes = 0;
        $count = function () use (&$writes) {
            $writes++;
        };

        add_action('update_option___fls_auth_settings', $count);
        add_action('add_option___fls_auth_settings', $count);

        Onboarding::complete([
            'two_fa'      => ['totp' => true, 'email' => true, 'roles' => ['administrator']],
            'login_limit' => ['limit' => 4, 'timing' => 20],
            'hardening'   => [
                'disable_xmlrpc'     => true,
                'disable_users_rest' => true,
                'secure_signup_form' => true
            ],
            'alerts'      => [
                'enabled' => true,
                'roles'   => ['administrator'],
                'email'   => '{admin_email}'
            ]
        ]);

        remove_action('update_option___fls_auth_settings', $count);
        remove_action('add_option___fls_auth_settings', $count);

        $this->assertSame(1, $writes);
    }

    /** A refused answer must not leave the settings half written. */
    public function test_a_refusal_writes_nothing_at_all()
    {
        $before = get_option('__fls_auth_settings');

        $error = Onboarding::complete([
            'hardening'   => ['disable_xmlrpc' => true],
            'login_limit' => ['limit' => 0, 'timing' => 0]
        ]);

        $this->assertWPError($error);
        $this->assertSame($before, get_option('__fls_auth_settings'));
        $this->assertFalse(Onboarding::isDone());
    }

    public function test_the_applied_list_names_only_what_changed()
    {
        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['disable_xmlrpc' => 'yes']
        ));
        Helper::resetStatics();

        $result = Onboarding::complete([
            'hardening' => [
                'disable_xmlrpc'     => true,
                'disable_users_rest' => true,
                'secure_signup_form' => false
            ]
        ]);

        $applied = implode(' | ', $result['applied']);

        $this->assertStringNotContainsString('XML-RPC', $applied);
        $this->assertStringContainsString('user list', $applied);
    }

    /** A step nobody answered is left alone rather than defaulted into. */
    public function test_an_unanswered_step_changes_nothing()
    {
        Onboarding::complete(['hardening' => ['disable_xmlrpc' => true]]);

        $this->assertSame('no', Helper::getSetting('totp_2fa'));
        $this->assertSame([], Helper::getSetting('notification_user_roles'));
    }

    /* --------------------------------------------------------------- the steps */

    public function test_the_step_list_opens_on_the_recommended_values()
    {
        $recommended = Helper::getRecommendedSettings();
        $steps = $this->keyedSteps();

        $this->assertTrue($steps['two_fa']['answer']['totp']);
        $this->assertSame(
            $recommended['totp_2fa_roles'],
            $steps['two_fa']['answer']['roles']
        );
        $this->assertSame(
            (int)$recommended['login_try_limit'],
            $steps['login_limit']['answer']['limit']
        );
    }

    /**
     * The guard against the wizard and the checklist drifting apart. Every check a step
     * claims to satisfy has to exist, or a screen is quietly showing nothing where the
     * reasoning for a toggle should be.
     */
    public function test_every_check_a_step_names_actually_exists()
    {
        $named = 0;

        foreach (Onboarding::steps() as $step) {
            foreach ($step['checks'] as $check) {
                $this->assertNotNull(SecurityChecks::find($check['key']));
                $this->assertNotSame('', $check['title']);
                $this->assertNotSame('', $check['why']);
                $named++;
            }
        }

        $this->assertGreaterThan(0, $named);
    }

    public function test_every_step_carries_the_copy_its_screen_needs()
    {
        foreach (Onboarding::steps() as $step) {
            $this->assertNotSame('', $step['title'], $step['id']);
            $this->assertNotSame('', $step['headline'], $step['id']);
            $this->assertNotSame('', $step['why'], $step['id']);
            $this->assertNotSame('', $step['preview'], $step['id']);
        }
    }

    /**
     * Asked only where the answer can change something. A site with a working declared
     * proxy would answer "yes, that is my address" for the opposite reason to a site with
     * no proxy at all, and there is nothing safe to do with an answer that ambiguous.
     */
    public function test_the_connection_step_is_dropped_once_a_proxy_is_declared()
    {
        $this->behindAnUndeclaredProxy();

        $this->assertArrayHasKey('connection', $this->keyedSteps());

        update_option('__fls_auth_settings', array_merge(
            get_option('__fls_auth_settings'),
            ['trusted_proxies' => '10.0.0.1']
        ));
        Helper::resetStatics();

        $this->assertArrayNotHasKey('connection', $this->keyedSteps());
    }

    /**
     * Nearly every WordPress site is in this state, and in it the question has one
     * available answer: the one already true. So it is not asked.
     */
    public function test_the_connection_step_is_not_offered_without_a_proxy()
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.24';
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        Helper::resetStatics();

        $this->assertArrayNotHasKey('connection', $this->keyedSteps());
    }

    public function test_the_connection_step_cannot_be_skipped_under_an_undeclared_proxy()
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9';
        Helper::resetStatics();

        $steps = $this->keyedSteps();

        $this->assertArrayHasKey('connection', $steps);
        $this->assertFalse($steps['connection']['skippable']);
    }

    public function test_every_other_step_can_always_be_left()
    {
        foreach (Onboarding::steps() as $step) {
            if ($step['id'] === 'connection') {
                continue;
            }

            $this->assertTrue($step['skippable'], $step['id']);
        }
    }

    public function test_the_payload_carries_what_the_screens_need()
    {
        $payload = Onboarding::payload();

        foreach (['steps', 'settings', 'recommended', 'user_roles', 'connection', 'admin_email'] as $key) {
            $this->assertArrayHasKey($key, $payload);
        }

        $this->assertNotEmpty($payload['steps']);
        $this->assertArrayHasKey('resolved_ip', $payload['connection']);
    }

    /**
     * @return array steps keyed by id
     */
    private function keyedSteps()
    {
        $keyed = [];

        foreach (Onboarding::steps() as $step) {
            $keyed[$step['id']] = $step;
        }

        return $keyed;
    }
}
