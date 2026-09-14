<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\TwoFa\FactorStore;
use FluentAuth\App\Services\TwoFa\SecretCipher;
use FluentAuth\App\Services\TwoFa\SecretKey;
use FluentAuth\App\Services\TwoFa\SecretMigration;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * Encryption of the authenticator secret, and every way the key can go wrong.
 *
 * The tests that matter most here are the failure ones. Encrypting and decrypting under a
 * key that is present is the easy half and would pass on the first attempt; what this
 * feature has to be trusted for is what happens when the key is rotated, deleted or
 * replaced - because those are silent, they happen months later, and the wrong answer to
 * any of them is either a site full of unreadable secrets or an administrator locked out.
 */
class SecretEncryptionTest extends BaseTestCase
{
    protected $keyValue = '';

    public function setUp(): void
    {
        parent::setUp();

        SecretKey::forget();

        $this->keyValue = 'test-key-one';

        /*
         * The constant cannot be defined and undefined between tests, so the key material
         * is supplied through the filter that exists for installs which keep it outside
         * wp-config.php. Changing a key is then a matter of changing this value.
         */
        add_filter('fluent_auth/secret_key_material', [$this, 'supplyMaterial'], 10);
    }

    public function tearDown(): void
    {
        remove_filter('fluent_auth/secret_key_material', [$this, 'supplyMaterial'], 10);

        SecretKey::forget();

        parent::tearDown();
    }

    public function supplyMaterial($material)
    {
        return $this->keyValue;
    }

    /** @test */
    public function it_round_trips_a_secret_through_the_cipher()
    {
        $key = SecretKey::derive('some-key');

        $protected = SecretCipher::protect('JBSWY3DPEHPK3PXP', $key);

        $this->assertTrue(SecretCipher::isProtected($protected));
        $this->assertStringNotContainsString('JBSWY3DPEHPK3PXP', $protected);
        $this->assertEquals('JBSWY3DPEHPK3PXP', SecretCipher::reveal($protected, $key));
    }

    /** @test */
    public function it_refuses_a_ciphertext_under_a_different_key()
    {
        $protected = SecretCipher::protect('JBSWY3DPEHPK3PXP', SecretKey::derive('key-a'));

        $this->assertFalse(SecretCipher::reveal($protected, SecretKey::derive('key-b')));
    }

    /**
     * The reason for GCM rather than CBC. A tampered ciphertext must fail, not decrypt to
     * something else that happens to look like a base32 secret.
     *
     * @test
     */
    public function it_refuses_a_tampered_ciphertext()
    {
        $key = SecretKey::derive('some-key');
        $protected = SecretCipher::protect('JBSWY3DPEHPK3PXP', $key);

        $parts = explode('$', $protected);
        $payload = $parts[3];
        // Flip one character of the payload, keeping it valid base64url.
        $parts[3] = ($payload[0] === 'A' ? 'B' : 'A') . substr($payload, 1);

        $this->assertFalse(SecretCipher::reveal(implode('$', $parts), $key));
    }

    /** @test */
    public function it_leaves_plaintext_alone_when_encryption_is_off()
    {
        $this->assertFalse(SecretKey::isEnabled());
        $this->assertEquals(SecretKey::STATE_OFF, SecretKey::diagnose());

        $userId = $this->factory->user->create();

        FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'status'  => FactorStore::STATUS_ACTIVE,
            'secret'  => 'JBSWY3DPEHPK3PXP'
        ]);

        $this->assertEquals('JBSWY3DPEHPK3PXP', $this->storedSecret($userId));
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
    }

    /** @test */
    public function it_encrypts_a_new_secret_once_switched_on()
    {
        $this->assertTrue(SecretKey::adopt());

        $userId = $this->factory->user->create();

        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        // Stored encrypted...
        $this->assertTrue(SecretCipher::isProtected($this->storedSecret($userId)));
        $this->assertStringNotContainsString('JBSWY3DPEHPK3PXP', $this->storedSecret($userId));

        // ...and read back transparently by everything above the store.
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($userId));
    }

    /** @test */
    public function it_encrypts_secrets_that_were_already_stored()
    {
        $userId = $this->factory->user->create();

        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');
        $this->assertEquals('JBSWY3DPEHPK3PXP', $this->storedSecret($userId));
        $this->assertEquals(1, SecretMigration::plaintextCount());

        SecretKey::adopt();

        $this->assertEquals(1, SecretMigration::encryptAll());
        $this->assertTrue(SecretCipher::isProtected($this->storedSecret($userId)));
        $this->assertEquals(0, SecretMigration::plaintextCount());
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));

        // Running it again is a no-op rather than a double encryption.
        $this->assertEquals(0, SecretMigration::encryptAll());
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
    }

    /** @test */
    public function it_puts_secrets_back_in_the_clear_when_switched_off()
    {
        $userId = $this->factory->user->create();

        SecretKey::adopt();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->assertEquals(1, SecretMigration::decryptAll());
        $this->assertEquals('JBSWY3DPEHPK3PXP', $this->storedSecret($userId));

        SecretKey::forget();

        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
    }

    /**
     * The whole point of the canary: the site can tell that the key changed without ever
     * having stored the key.
     *
     * @test
     */
    public function it_reports_a_changed_key_rather_than_just_a_failure()
    {
        SecretKey::adopt();

        $this->assertEquals(SecretKey::STATE_OK, SecretKey::diagnose());
        $this->assertTrue(SecretKey::isHealthy());

        $this->keyValue = 'test-key-two';

        $this->assertEquals(SecretKey::STATE_KEY_CHANGED, SecretKey::diagnose());
        $this->assertFalse(SecretKey::isHealthy());
    }

    /** @test */
    public function it_reports_a_missing_constant_separately_from_a_changed_one()
    {
        SecretKey::adopt();

        // wp-config.php overwritten by a deploy: the line is simply gone.
        $this->keyValue = '';

        $this->assertEquals(SecretKey::STATE_CONSTANT_MISSING, SecretKey::diagnose());
    }

    /**
     * A lost key must cost an enrollment and nothing more. The user is reported as not
     * enrolled, which is what sends them to pair a new phone rather than to a code prompt
     * that can never be satisfied.
     *
     * @test
     */
    public function an_unreadable_secret_reads_as_not_enrolled_rather_than_locking_anybody_out()
    {
        $userId = $this->factory->user->create();

        SecretKey::adopt();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->assertTrue(TotpTwoFaMethod::isEnrolled($userId));

        $this->keyValue = 'test-key-two';

        $this->assertEquals('', TotpTwoFaMethod::getSecret($userId));
        $this->assertFalse(TotpTwoFaMethod::isEnrolled($userId));
        $this->assertEquals(1, SecretMigration::unreadableCount());

        $row = FactorStore::firstForUser($userId, FactorStore::TYPE_TOTP);
        $this->assertTrue($row->secret_unreadable);
    }

    /** @test */
    public function it_re_keys_from_the_old_value_to_the_new_one()
    {
        $userId = $this->factory->user->create();

        SecretKey::adopt();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->keyValue = 'test-key-two';
        $this->assertEquals(SecretKey::STATE_KEY_CHANGED, SecretKey::diagnose());

        $result = SecretMigration::rekey('test-key-one');

        $this->assertEquals(1, $result['changed']);
        $this->assertEquals(0, $result['failed']);
        $this->assertEquals(SecretKey::STATE_OK, SecretKey::diagnose());
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($userId));
    }

    /**
     * A wrong paste must change nothing at all. Half a table converted under a key nobody
     * has is worse than the state it started in.
     *
     * @test
     */
    public function it_refuses_a_wrong_old_key_without_touching_a_row()
    {
        $userId = $this->factory->user->create();

        SecretKey::adopt();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $before = $this->storedSecret($userId);

        $this->keyValue = 'test-key-two';

        $this->assertWpErrorWithCode(SecretMigration::rekey('not-the-old-key'), 'wrong_old_key');
        $this->assertEquals($before, $this->storedSecret($userId));
        $this->assertEquals(SecretKey::STATE_KEY_CHANGED, SecretKey::diagnose());
    }

    /**
     * Encryption on, key gone, somebody enrolling. Storing the secret in the clear here
     * would quietly undo the site's own decision, so the enrollment fails instead.
     *
     * @test
     */
    public function it_refuses_to_store_a_secret_it_cannot_encrypt()
    {
        SecretKey::adopt();

        $this->keyValue = '';

        $userId = $this->factory->user->create();

        $stored = FactorStore::insert([
            'user_id' => $userId,
            'type'    => FactorStore::TYPE_TOTP,
            'status'  => FactorStore::STATUS_ACTIVE,
            'secret'  => 'JBSWY3DPEHPK3PXP'
        ]);

        $this->assertWpErrorWithCode($stored, 'secret_not_protected');
        $this->assertFalse(TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP'));
    }

    /**
     * A passkey's "secret" is a public key. Encrypting it would be pointless work, and
     * more to the point the passkey login path reads it directly.
     *
     * @test
     */
    public function it_never_encrypts_a_passkey_public_key()
    {
        SecretKey::adopt();

        $userId = $this->factory->user->create();

        FactorStore::insert([
            'user_id'    => $userId,
            'type'       => FactorStore::TYPE_PASSKEY,
            'status'     => FactorStore::STATUS_ACTIVE,
            'identifier' => 'credential-id-one',
            'secret'     => '-----BEGIN PUBLIC KEY-----abc-----END PUBLIC KEY-----'
        ]);

        $row = FactorStore::firstForUser($userId, FactorStore::TYPE_PASSKEY);

        $this->assertEquals('-----BEGIN PUBLIC KEY-----abc-----END PUBLIC KEY-----', $row->secret);
        $this->assertFalse(SecretCipher::isProtected($this->storedSecret($userId, FactorStore::TYPE_PASSKEY)));
    }

    /** @test */
    public function it_encrypts_a_pending_setup_too()
    {
        SecretKey::adopt();

        $userId = $this->factory->user->create();

        $pending = TotpTwoFaMethod::getOrCreatePendingSecret($userId);

        $this->assertNotEmpty($pending);
        $this->assertTrue(SecretCipher::isProtected($this->storedSecret($userId, FactorStore::TYPE_TOTP, FactorStore::STATUS_PENDING)));
        $this->assertEquals($pending, TotpTwoFaMethod::getPendingSecret($userId));
    }

    /**
     * There is no fallback key. AUTH_SALT was the obvious one and is deliberately not
     * offered: rotating salts is ordinary advice, and a key with an expiry date nobody set
     * is worse than none, because the site believes it is protected.
     *
     * @test
     */
    public function it_has_no_fallback_key_when_the_constant_is_absent()
    {
        $this->keyValue = '';

        $this->assertFalse(SecretKey::hasKey());
        $this->assertEquals('', SecretKey::current());
        $this->assertFalse(SecretKey::adopt());
        $this->assertFalse(SecretKey::isEnabled());

        // And a secret written in that state is stored exactly as it always was.
        $userId = $this->factory->user->create();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->assertEquals('JBSWY3DPEHPK3PXP', $this->storedSecret($userId));
        $this->assertTrue(TotpTwoFaMethod::isEnrolled($userId));
    }

    /**
     * The stored form, read past the layer that decrypts it.
     *
     * @return string
     */
    protected function storedSecret($userId, $type = FactorStore::TYPE_TOTP, $status = FactorStore::STATUS_ACTIVE)
    {
        $row = flsDb()->table('fls_auth_factors')
            ->where('user_id', $userId)
            ->where('type', $type)
            ->where('status', $status)
            ->first();

        return $row ? (string)$row->secret : '';
    }
}
