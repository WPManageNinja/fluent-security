<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Hooks\Handlers\TwoFaHandler;
use FluentAuth\App\Services\TwoFa\TotpProvider;
use FluentAuth\App\Services\TwoFa\PasskeyTwoFaMethod;
use FluentAuth\App\Services\TwoFa\RecoveryCodes;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;
use FluentAuth\App\Services\TwoFa\TwoFaService;
use FluentAuth\App\Services\TwoFa\WebAuthn\Base64Url;
use FluentAuth\App\Services\TwoFa\WebAuthn\PasskeyStore;
use FluentAuth\App\Services\TwoFa\WebAuthn\Registration;
use FluentAuth\App\Services\TwoFa\WebAuthn\UserHandle;

/**
 * The passkey method as the rest of the plugin sees it, and the store behind it.
 */
class PasskeyTwoFaMethodTest extends BaseTestCase
{
    /** @var WebAuthnFixture */
    private $authenticator;

    public function setUp(): void
    {
        parent::setUp();

        update_option('home', 'https://example.org');
        update_option('siteurl', 'https://example.org');

        PasskeyStore::ensureTable();

        $this->authenticator = new WebAuthnFixture();

        $this->setSettings([
            'passkey_2fa'       => 'yes',
            'passkey_2fa_roles' => ['administrator']
        ]);
    }

    public function tearDown(): void
    {
        remove_all_filters('fluent_auth/passkey_allow_without_fallback');
        TwoFaService::resetMethods();
        parent::tearDown();
    }

    // ------------------------------------------------------------------- the store

    public function test_a_credential_can_be_stored_and_found_by_its_own_id()
    {
        $user = $this->makeAdmin();
        $verified = $this->enrol($user, 'Work laptop');

        $found = PasskeyStore::findByCredentialId($verified['credential_id']);

        $this->assertNotNull($found);
        $this->assertEquals($user->ID, $found->user_id);
        $this->assertSame('Work laptop', $found->label);
        $this->assertSame(1, PasskeyStore::countForUser($user));
    }

    /**
     * Section 7.1 step 20. Re-pointing an existing credential at a new account would be
     * a way to take one over.
     */
    public function test_the_same_credential_cannot_be_registered_twice()
    {
        $user = $this->makeAdmin();
        $other = $this->makeAdmin();

        $verified = $this->enrol($user);

        $again = PasskeyStore::add($other, $verified, 'Stolen');

        $this->assertWpErrorWithCode($again, 'already_registered');
        $this->assertSame(0, PasskeyStore::countForUser($other));
    }

    public function test_a_passkey_cannot_be_removed_by_somebody_it_does_not_belong_to()
    {
        $owner = $this->makeAdmin();
        $stranger = $this->makeAdmin();

        $this->enrol($owner);
        $credential = PasskeyStore::getForUser($owner)[0];

        $this->assertFalse(PasskeyStore::delete($credential->id, $stranger));
        $this->assertSame(1, PasskeyStore::countForUser($owner));

        $this->assertTrue(PasskeyStore::delete($credential->id, $owner));
        $this->assertSame(0, PasskeyStore::countForUser($owner));
    }

    public function test_clearing_an_account_also_forgets_its_user_handle()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);
        UserHandle::getOrCreate($user);

        $this->assertNotSame('', UserHandle::get($user));

        PasskeyStore::deleteAllForUser($user);

        $this->assertSame(0, PasskeyStore::countForUser($user));
        $this->assertSame('', UserHandle::get($user));
    }

    public function test_a_use_is_recorded_against_the_credential()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $credential = PasskeyStore::getForUser($user)[0];
        PasskeyStore::touch($credential, 42);

        $refreshed = PasskeyStore::findByCredentialId($credential->credential_id);

        $this->assertEquals(42, $refreshed->sign_count);
        $this->assertNotEmpty($refreshed->last_used_at);
    }

    // ------------------------------------------------------------------ the method

    public function test_the_method_key_fits_the_column_that_records_it()
    {
        // fls_login_hashes.use_type is varchar(20).
        $this->assertLessThanOrEqual(20, strlen((new PasskeyTwoFaMethod())->getKey()));
    }

    public function test_a_passkey_is_asked_for_before_an_authenticator_app()
    {
        $keys = array_keys(TwoFaService::getMethods());

        $this->assertSame('passkey', $keys[0]);
        $this->assertLessThan(array_search('totp', $keys, true), array_search('passkey', $keys, true));
    }

    public function test_the_method_is_off_for_a_role_that_was_not_named()
    {
        $editor = get_user_by('ID', $this->factory->user->create(['role' => 'editor']));

        $this->assertFalse(PasskeyTwoFaMethod::isAllowedForUser($editor));
        $this->assertTrue(PasskeyTwoFaMethod::isAllowedForUser($this->makeAdmin()));
    }

    public function test_the_method_is_off_on_a_site_that_is_not_served_securely()
    {
        update_option('home', 'http://example.org');

        $this->assertFalse(PasskeyTwoFaMethod::isAllowedForUser($this->makeAdmin()));
        $this->assertFalse(PasskeyTwoFaMethod::isEnabledForAnyRole());
    }

    /**
     * The rule that keeps a passkey from becoming the only way into an account.
     */
    public function test_a_lone_passkey_is_not_challenged_with()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $method = new PasskeyTwoFaMethod();

        $this->assertTrue(PasskeyTwoFaMethod::isEnrolled($user));
        $this->assertFalse($method->isAvailableForUser($user));
    }

    public function test_a_second_passkey_makes_the_first_usable()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $this->authenticator = new WebAuthnFixture();
        $this->enrol($user, 'Phone');

        $this->assertSame(2, PasskeyStore::countForUser($user));
        $this->assertTrue((new PasskeyTwoFaMethod())->isAvailableForUser($user));
    }

    public function test_an_authenticator_app_also_counts_as_the_fallback()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        TotpTwoFaMethod::activate($user, 'JBSWY3DPEHPK3PXP');

        $this->assertTrue((new PasskeyTwoFaMethod())->isAvailableForUser($user));
    }

    /**
     * The reason recovery codes were worth moving out of the authenticator app. A
     * passkey has nothing to type; a printed code is exactly what a device-bound
     * credential lacks, so one passkey plus codes is a legitimate setup.
     */
    public function test_recovery_codes_make_a_lone_passkey_usable()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $this->assertFalse((new PasskeyTwoFaMethod())->isAvailableForUser($user));

        RecoveryCodes::generate($user);

        $this->assertTrue((new PasskeyTwoFaMethod())->isAvailableForUser($user));
    }

    public function test_a_recovery_code_answers_the_passkey_challenge()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $codes = RecoveryCodes::generate($user);

        $method = new PasskeyTwoFaMethod();
        $logHash = (object)$method->prepareChallenge($user)['columns'];

        $this->assertTrue($method->verifyProof($user, $logHash, ['login_passcode' => $codes[0]]));
        $this->assertFalse($method->verifyProof($user, $logHash, ['login_passcode' => $codes[0]]));
        $this->assertSame(RecoveryCodes::CODE_COUNT - 1, RecoveryCodes::countRemaining($user));
    }

    public function test_something_that_is_not_a_recovery_code_is_reported_rather_than_counted()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);
        RecoveryCodes::generate($user);

        $method = new PasskeyTwoFaMethod();
        $logHash = (object)$method->prepareChallenge($user)['columns'];

        $this->assertWpErrorWithCode(
            $method->verifyProof($user, $logHash, ['login_passcode' => '123456']),
            'passkey_bad_recovery'
        );
    }

    public function test_a_site_may_allow_a_lone_passkey_on_purpose()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        add_filter('fluent_auth/passkey_allow_without_fallback', '__return_true');

        $this->assertTrue((new PasskeyTwoFaMethod())->isAvailableForUser($user));
    }

    /**
     * The way out of a challenge the user cannot answer - a passkey on a browser with
     * no WebAuthn, say. It has to exist, and it has to move sideways rather than down.
     */
    public function test_a_passkey_challenge_can_be_swapped_for_an_authenticator_app()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $this->setSettings(['totp_2fa' => 'yes', 'totp_2fa_roles' => ['administrator']]);
        TotpTwoFaMethod::activate($user, 'JBSWY3DPEHPK3PXP');

        $alternative = TwoFaService::getAlternativeMethod($user, new PasskeyTwoFaMethod());

        $this->assertNotNull($alternative);
        $this->assertSame('totp', $alternative->getKey());
    }

    /**
     * A switch must never be a way to be asked for less. An emailed code proves the
     * mailbox, not a device, so it is not an alternative to either device factor.
     */
    public function test_a_device_factor_cannot_be_swapped_for_a_mailed_code()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $this->setSettings([
            'totp_2fa'     => 'no',
            'email2fa'     => 'yes',
            'email2fa_roles' => ['administrator']
        ]);

        $this->assertNull(TwoFaService::getAlternativeMethod($user, new PasskeyTwoFaMethod()));
    }

    public function test_the_switch_url_carries_the_pending_login()
    {
        $url = TwoFaService::getSwitchUrl('abc123');

        $this->assertStringContainsString('login_hash=abc123', $url);
        $this->assertStringContainsString('action=' . TwoFaService::SWITCH_ACTION, $url);
    }

    // ------------------------------------------------------------------ the ceremony

    public function test_a_challenge_is_issued_into_the_pending_row()
    {
        $challenge = (new PasskeyTwoFaMethod())->prepareChallenge($this->makeAdmin());

        $raw = Base64Url::decode($challenge['columns'][PasskeyTwoFaMethod::CHALLENGE_COLUMN]);

        $this->assertSame(32, strlen($raw));
        $this->assertNull($challenge['secret']);
        // The column is varchar(100).
        $this->assertLessThanOrEqual(100, strlen($challenge['columns'][PasskeyTwoFaMethod::CHALLENGE_COLUMN]));
    }

    public function test_a_signed_assertion_completes_the_challenge()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $method = new PasskeyTwoFaMethod();
        $challenge = $method->prepareChallenge($user);
        $logHash = (object)$challenge['columns'];

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => Base64Url::decode($challenge['columns'][PasskeyTwoFaMethod::CHALLENGE_COLUMN]),
            'signCount' => 5
        ]);

        $this->assertTrue($method->verifyProof($user, $logHash, [
            'webauthn_response' => wp_json_encode($response)
        ]));

        $credential = PasskeyStore::getForUser($user)[0];
        $this->assertEquals(5, $credential->sign_count);
    }

    public function test_an_assertion_from_an_unregistered_passkey_is_refused()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $method = new PasskeyTwoFaMethod();
        $challenge = $method->prepareChallenge($user);
        $logHash = (object)$challenge['columns'];

        $stranger = new WebAuthnFixture();
        $response = $stranger->createAssertionResponse([
            'challenge' => Base64Url::decode($challenge['columns'][PasskeyTwoFaMethod::CHALLENGE_COLUMN])
        ]);

        $this->assertWpErrorWithCode(
            $method->verifyProof($user, $logHash, ['webauthn_response' => wp_json_encode($response)]),
            'passkey_unknown'
        );
    }

    /**
     * A wrong answer is false, which spends an attempt. A WP_Error would not.
     */
    public function test_a_forged_assertion_counts_as_a_failed_attempt()
    {
        $user = $this->makeAdmin();
        $this->enrol($user);

        $method = new PasskeyTwoFaMethod();
        $challenge = $method->prepareChallenge($user);
        $logHash = (object)$challenge['columns'];

        $response = $this->authenticator->createAssertionResponse([
            'challenge' => Base64Url::decode($challenge['columns'][PasskeyTwoFaMethod::CHALLENGE_COLUMN]),
            'tamper'    => true
        ]);

        $this->assertFalse($method->verifyProof($user, $logHash, [
            'webauthn_response' => wp_json_encode($response)
        ]));
    }

    public function test_a_missing_response_is_reported_rather_than_counted()
    {
        $method = new PasskeyTwoFaMethod();
        $user = $this->makeAdmin();
        $logHash = (object)$method->prepareChallenge($user)['columns'];

        $this->assertWpErrorWithCode($method->verifyProof($user, $logHash, []), 'passkey_missing');
    }

    // ------------------------------------------------------------- switching method

    public function test_switching_method_keeps_the_wrong_guesses()
    {
        $this->setSettings([
            'totp_2fa'       => 'yes',
            'totp_2fa_roles' => ['administrator']
        ]);

        $user = $this->makeAdmin();
        $this->enrol($user);
        TotpTwoFaMethod::activate($user, TotpProvider::generateSecret());

        $handler = new TwoFaHandler();
        $first = $handler->sendAndGet2FaConfirmFormUrl($user, 'both', null, null, false);

        flsDb()->table('fls_login_hashes')
            ->where('login_hash', $first['login_hash'])
            ->update(['used_count' => 3]);

        $firstType = flsDb()->table('fls_login_hashes')
            ->where('login_hash', $first['login_hash'])
            ->first()->use_type;

        $toTotp = $this->switchFrom($handler, $first['login_hash']);
        $this->assertNotSame($firstType, $toTotp->use_type);
        $this->assertEquals(3, $toTotp->used_count);

        $back = $this->switchFrom($handler, $toTotp->login_hash);
        $this->assertSame($firstType, $back->use_type);
        $this->assertEquals(3, $back->used_count);
    }

    public function test_switching_before_any_wrong_guess_starts_at_zero()
    {
        $this->setSettings([
            'totp_2fa'       => 'yes',
            'totp_2fa_roles' => ['administrator']
        ]);

        $user = $this->makeAdmin();
        $this->enrol($user);
        TotpTwoFaMethod::activate($user, TotpProvider::generateSecret());

        $handler = new TwoFaHandler();
        $first = $handler->sendAndGet2FaConfirmFormUrl($user, 'both', null, null, false);

        $this->assertEquals(0, $this->switchFrom($handler, $first['login_hash'])->used_count);
    }

    public function test_a_switch_that_loses_the_race_opens_no_challenge()
    {
        list($handler, $hash) = $this->userWithBothMethods();

        // Another switch closes the row between this one reading it and closing it.
        $this->beforeTheSwitchCloses(function ($wpdb, $table) use ($hash) {
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET status = 'failed' WHERE login_hash = %s", $hash));
        });

        $this->runSwitch($handler, $hash);

        $this->assertSame(0, flsDb()->table('fls_login_hashes')->where('status', 'issued')->count());
    }

    public function test_a_guess_made_during_the_switch_is_carried_over()
    {
        list($handler, $hash) = $this->userWithBothMethods();

        // Two wrong guesses land after the switch read the row, before it closed it.
        $this->beforeTheSwitchCloses(function ($wpdb, $table) use ($hash) {
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET used_count = used_count + 2 WHERE login_hash = %s", $hash));
        });

        $this->runSwitch($handler, $hash);

        $row = flsDb()->table('fls_login_hashes')->where('status', 'issued')->first();
        $this->assertEquals(2, $row->used_count);
    }

    /**
     * @return array [TwoFaHandler, string the first challenge's hash]
     */
    private function userWithBothMethods()
    {
        $this->setSettings([
            'totp_2fa'       => 'yes',
            'totp_2fa_roles' => ['administrator']
        ]);

        $user = $this->makeAdmin();
        $this->enrol($user);
        TotpTwoFaMethod::activate($user, TotpProvider::generateSecret());

        $handler = new TwoFaHandler();
        $first = $handler->sendAndGet2FaConfirmFormUrl($user, 'both', null, null, false);

        return [$handler, $first['login_hash']];
    }

    /**
     * Runs $change once, just before switchMethod() closes the old row: the moment a
     * parallel request could get there first.
     */
    private function beforeTheSwitchCloses(callable $change)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'fls_login_hashes';
        $done = false;

        add_filter('query', function ($query) use (&$done, $change, $wpdb, $table) {
            if (!$done && preg_match('/^UPDATE\s+`?' . preg_quote($table, '/') . '`?\s+SET.*status`?\s*=\s*\'failed\'/is', $query)) {
                $done = true;
                $change($wpdb, $table);
            }
            return $query;
        });
    }

    private function runSwitch(TwoFaHandler $handler, $hash)
    {
        $_REQUEST['login_hash'] = $hash;

        $stop = function () {
            throw new \RuntimeException('redirected');
        };
        add_filter('wp_redirect', $stop);

        try {
            $handler->switchMethod();
        } catch (\RuntimeException $e) {
            // The exit() after the redirect.
        } finally {
            remove_filter('wp_redirect', $stop);
            remove_all_filters('query');
            unset($_REQUEST['login_hash']);
        }
    }

    /**
     * @return object the challenge row the switch issued
     */
    private function switchFrom(TwoFaHandler $handler, $hash)
    {
        $_REQUEST['login_hash'] = $hash;

        $stop = function () {
            throw new \RuntimeException('redirected');
        };
        add_filter('wp_redirect', $stop);

        try {
            $handler->switchMethod();
            $this->fail('Expected a redirect.');
        } catch (\RuntimeException $e) {
            // The exit() after the redirect.
        } finally {
            remove_filter('wp_redirect', $stop);
            unset($_REQUEST['login_hash']);
        }

        $row = flsDb()->table('fls_login_hashes')
            ->where('status', 'issued')
            ->orderBy('id', 'DESC')
            ->first();

        $this->assertNotNull($row, 'the switch should issue a new challenge');
        $this->assertNotSame($hash, $row->login_hash);

        return $row;
    }

    // ----------------------------------------------------------------- scaffolding

    /**
     * @return \WP_User
     */
    private function makeAdmin()
    {
        return get_user_by('ID', $this->factory->user->create(['role' => 'administrator']));
    }

    /**
     * @param $user \WP_User
     * @param $label string
     * @return array
     */
    private function enrol($user, $label = 'Test key')
    {
        $challenge = random_bytes(32);
        $response = $this->authenticator->createRegistrationResponse(['challenge' => $challenge]);
        $verified = Registration::verify($response, $challenge);

        PasskeyStore::add($user, $verified, $label);

        return $verified;
    }

    /**
     * @param $settings array
     * @return void
     */
    private function setSettings($settings)
    {
        update_option('__fls_auth_settings', array_merge(
            (array)get_option('__fls_auth_settings'),
            $settings
        ));

        Helper::resetStatics();
    }
}
