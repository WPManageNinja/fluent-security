<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Helpers\Helper;
use FluentAuth\App\Services\Checks\Config\SecretEncryptionCheck;
use FluentAuth\App\Services\Checks\Dismissals;
use FluentAuth\App\Services\Checks\Finding;
use FluentAuth\App\Services\TwoFa\SecretKey;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * What the security screen says about the encryption key.
 *
 * The row this check draws is the only thing standing between "a deploy overwrote
 * wp-config.php" and "why is my authenticator app not working" three weeks later, so what
 * is pinned here is that each cause gets its own words. Both are recoverable, and a single
 * "decryption failed" would hide that either can be undone at all.
 */
class SecretEncryptionCheckTest extends BaseTestCase
{
    protected $keyValue = '';

    public function setUp(): void
    {
        parent::setUp();

        SecretKey::forget();
        delete_option(Dismissals::OPTION);

        $this->keyValue = 'check-key-one';

        add_filter('fluent_auth/secret_key_material', [$this, 'supplyMaterial'], 10);

        update_option('__fls_auth_settings', [
            'totp_2fa'       => 'yes',
            'totp_2fa_roles' => ['administrator']
        ]);

        Helper::resetStatics();
    }

    public function tearDown(): void
    {
        remove_filter('fluent_auth/secret_key_material', [$this, 'supplyMaterial'], 10);

        SecretKey::forget();
        delete_option(Dismissals::OPTION);
        delete_option('__fls_auth_settings');

        parent::tearDown();
    }

    public function supplyMaterial($material)
    {
        return $this->keyValue;
    }

    protected function only($findings)
    {
        $this->assertCount(1, $findings);

        return $findings[0]->toArray();
    }

    /** @test */
    public function it_says_nothing_on_a_site_with_no_authenticator_app_on_offer()
    {
        update_option('__fls_auth_settings', ['totp_2fa' => 'no', 'totp_2fa_roles' => []]);
        Helper::resetStatics();

        $this->assertSame([], (new SecretEncryptionCheck())->run());
    }

    /**
     * Advice, not a fault. It is how nearly every plugin stores a TOTP secret, and the fix
     * needs a text editor - so it must not be drawn in the same colour as a changed file.
     *
     * @test
     */
    public function unencrypted_secrets_are_advice_rather_than_an_alarm()
    {
        $finding = $this->only((new SecretEncryptionCheck())->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_ADVICE, $finding['severity']);
        $this->assertFalse($finding['scored']);
        $this->assertStringContainsString('unencrypted', $finding['title']);
    }

    /** @test */
    public function it_passes_once_encryption_is_on()
    {
        SecretKey::adopt();

        $finding = $this->only((new SecretEncryptionCheck())->run());

        $this->assertEquals(Finding::STATE_PASSED, $finding['state']);
    }

    /** @test */
    public function a_changed_key_is_reported_as_something_to_fix_and_says_it_may_be_recoverable()
    {
        $userId = $this->factory->user->create();

        SecretKey::adopt();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->keyValue = 'check-key-two';

        $finding = $this->only((new SecretEncryptionCheck())->run());

        $this->assertEquals(Finding::STATE_OPEN, $finding['state']);
        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('1 authenticator app', $finding['title']);
        $this->assertStringContainsString('previous value', implode(' ', $finding['details']));
        // And the reassurance that matters most, in the details rather than left implied.
        $this->assertStringContainsString('Nobody is locked out', implode(' ', $finding['details']));
    }

    /** @test */
    public function a_missing_constant_is_reported_as_a_line_to_put_back()
    {
        SecretKey::adopt();

        $this->keyValue = '';

        $finding = $this->only((new SecretEncryptionCheck())->run());

        $this->assertEquals(Finding::SEVERITY_FIX, $finding['severity']);
        $this->assertStringContainsString('no longer in your wp-config.php', implode(' ', $finding['details']));
    }

    /** @test */
    public function the_advice_can_be_dismissed()
    {
        $check = new SecretEncryptionCheck();

        $this->assertArrayHasKey('message', $check->accept($check->id()));

        $finding = $this->only($check->run());
        $this->assertEquals(Finding::STATE_ACCEPTED, $finding['state']);

        $check->unaccept($check->id());

        $this->assertEquals(Finding::STATE_OPEN, $this->only($check->run())['state']);
    }

    /**
     * A row reporting that stored data cannot be read is not a preference, and accept() is
     * reachable by anyone who can call the endpoint with an id.
     *
     * @test
     */
    public function an_unreadable_secret_cannot_be_marked_as_expected()
    {
        SecretKey::adopt();

        $this->keyValue = 'check-key-two';

        $check = new SecretEncryptionCheck();

        $this->assertWpErrorWithCode($check->accept($check->id()), 'not_acceptable');
        $this->assertEquals(Finding::STATE_OPEN, $this->only($check->run())['state']);
    }
}
