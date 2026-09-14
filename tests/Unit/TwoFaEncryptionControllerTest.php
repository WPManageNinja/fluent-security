<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Http\Controllers\TwoFaEncryptionController;
use FluentAuth\App\Services\TwoFa\SecretKey;
use FluentAuth\App\Services\TwoFa\TotpTwoFaMethod;

/**
 * The endpoints behind the toggle on the two-factor screen.
 *
 * What is worth testing here is not the happy path but the refusals: enabling with no key
 * in place, disabling while the key is unreachable, and re-keying with the wrong value.
 * Each of those, done wrongly, ends with secrets nobody can read - so each has to fail
 * loudly and change nothing.
 */
class TwoFaEncryptionControllerTest extends BaseTestCase
{
    protected $keyValue = '';

    public function setUp(): void
    {
        parent::setUp();

        SecretKey::forget();
        delete_transient(TwoFaEncryptionController::PROPOSAL_KEY);

        $this->keyValue = 'controller-key-one';

        add_filter('fluent_auth/secret_key_material', [$this, 'supplyMaterial'], 10);
    }

    public function tearDown(): void
    {
        remove_filter('fluent_auth/secret_key_material', [$this, 'supplyMaterial'], 10);

        SecretKey::forget();
        delete_transient(TwoFaEncryptionController::PROPOSAL_KEY);

        parent::tearDown();
    }

    public function supplyMaterial($material)
    {
        return $this->keyValue;
    }

    protected function request($params = [])
    {
        $request = new \WP_REST_Request();

        foreach ($params as $key => $value) {
            $request->set_param($key, $value);
        }

        return $request;
    }

    /** @test */
    public function it_reports_the_state_it_is_in()
    {
        $response = TwoFaEncryptionController::getStatus($this->request());
        $status = $response['encryption'];

        $this->assertTrue($status['supported']);
        $this->assertEquals(SecretKey::STATE_OFF, $status['state']);
        $this->assertFalse($status['enabled']);
        $this->assertTrue($status['has_key']);
        $this->assertEquals(SecretKey::CONSTANT, $status['constant_name']);
    }

    /**
     * The line has to be the same one across a reload, or the value somebody copied is not
     * the value the next screen is talking about.
     *
     * @test
     */
    public function it_offers_a_stable_line_to_copy_while_no_key_is_in_place()
    {
        $this->keyValue = '';

        $first = TwoFaEncryptionController::getStatus($this->request())['encryption'];
        $second = TwoFaEncryptionController::getStatus($this->request())['encryption'];

        $this->assertArrayHasKey('proposed_line', $first);
        $this->assertStringContainsString(SecretKey::CONSTANT, $first['proposed_line']);
        $this->assertEquals($first['proposed_line'], $second['proposed_line']);
    }

    /**
     * The live key must never also be in the options table - that is the leak the constant
     * exists to avoid. So the proposal is dropped the moment the constant is readable.
     *
     * @test
     */
    public function it_stops_offering_a_line_and_forgets_the_proposal_once_a_key_is_in_place()
    {
        $this->keyValue = '';

        $offered = TwoFaEncryptionController::getStatus($this->request())['encryption'];
        $this->assertArrayHasKey('proposed_line', $offered);
        $this->assertNotEmpty(get_transient(TwoFaEncryptionController::PROPOSAL_KEY));

        // The administrator has now pasted it in and the constant is readable.
        $this->keyValue = 'controller-key-one';

        $status = TwoFaEncryptionController::getStatus($this->request())['encryption'];

        $this->assertArrayNotHasKey('proposed_line', $status);
        $this->assertFalse(get_transient(TwoFaEncryptionController::PROPOSAL_KEY));
    }

    /** @test */
    public function it_encrypts_what_is_stored_when_switched_on()
    {
        $userId = $this->factory->user->create();
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $response = TwoFaEncryptionController::enable($this->request());

        $this->assertEquals(SecretKey::STATE_OK, $response['encryption']['state']);
        $this->assertTrue($response['encryption']['enabled']);
        $this->assertEquals(0, $response['encryption']['counts']['plaintext']);
        $this->assertStringContainsString('1', $response['message']);
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
    }

    /**
     * The most likely mistake in the whole flow: the line was copied but never saved. It
     * has to be an error that names the file, not a key adopted on trust.
     *
     * @test
     */
    public function it_refuses_to_switch_on_without_a_readable_key()
    {
        $this->keyValue = '';

        $error = TwoFaEncryptionController::enable($this->request());

        $this->assertWpErrorWithCode($error, 'key_not_readable');
        $this->assertWpErrorMessage($error, 'wp-config.php');
        $this->assertFalse(SecretKey::isEnabled());
    }

    /** @test */
    public function it_turns_encryption_off_and_decrypts_what_it_stored()
    {
        $userId = $this->factory->user->create();

        TwoFaEncryptionController::enable($this->request());
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $response = TwoFaEncryptionController::disable($this->request());

        $this->assertFalse($response['encryption']['enabled']);
        $this->assertEquals(SecretKey::STATE_OFF, $response['encryption']['state']);
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
    }

    /**
     * Turning it off needs the key, because the rows cannot be read without it. This is
     * why deleting the line from wp-config.php is not a way to switch encryption off.
     *
     * @test
     */
    public function it_refuses_to_turn_off_while_the_key_is_unreachable()
    {
        $userId = $this->factory->user->create();

        TwoFaEncryptionController::enable($this->request());
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->keyValue = '';

        $error = TwoFaEncryptionController::disable($this->request());

        $this->assertWpErrorWithCode($error, 'no_key');
        $this->assertTrue(SecretKey::isEnabled());
    }

    /** @test */
    public function it_re_keys_when_given_the_previous_value()
    {
        $userId = $this->factory->user->create();

        TwoFaEncryptionController::enable($this->request());
        TotpTwoFaMethod::activate($userId, 'JBSWY3DPEHPK3PXP');

        $this->keyValue = 'controller-key-two';

        $status = TwoFaEncryptionController::getStatus($this->request())['encryption'];
        $this->assertEquals(SecretKey::STATE_KEY_CHANGED, $status['state']);
        $this->assertEquals(1, $status['counts']['unreadable']);

        $response = TwoFaEncryptionController::rekey($this->request(['old_key' => 'controller-key-one']));

        $this->assertEquals(SecretKey::STATE_OK, $response['encryption']['state']);
        $this->assertEquals(0, $response['encryption']['counts']['unreadable']);
        $this->assertEquals('JBSWY3DPEHPK3PXP', TotpTwoFaMethod::getSecret($userId));
    }

    /** @test */
    public function it_refuses_an_empty_old_key()
    {
        TwoFaEncryptionController::enable($this->request());

        $this->assertWpErrorWithCode(
            TwoFaEncryptionController::rekey($this->request(['old_key' => '   '])),
            'no_old_key'
        );
    }

    /** @test */
    public function it_refuses_a_wrong_old_key()
    {
        TwoFaEncryptionController::enable($this->request());

        $this->keyValue = 'controller-key-two';

        $this->assertWpErrorWithCode(
            TwoFaEncryptionController::rekey($this->request(['old_key' => 'never-was-the-key'])),
            'wrong_old_key'
        );
    }

    /** @test */
    public function switching_on_twice_is_not_an_error()
    {
        TwoFaEncryptionController::enable($this->request());

        $response = TwoFaEncryptionController::enable($this->request());

        $this->assertTrue($response['encryption']['enabled']);
        $this->assertEquals(SecretKey::STATE_OK, $response['encryption']['state']);
    }

    /**
     * The write endpoint adds the line and stops there.
     *
     * It must not go on to switch encryption on, and the reason is the whole shape of this
     * flow: wp-config.php was loaded before this request started, so the constant it just
     * wrote is not defined in this process. Enabling here would commit rows to a key that
     * has never been read back from the file.
     *
     * @test
     */
    public function writing_the_config_does_not_switch_encryption_on_by_itself()
    {
        $dir = get_temp_dir() . 'fls-enc-ctrl-' . wp_generate_password(8, false);
        mkdir($dir);
        $path = $dir . '/wp-config.php';
        file_put_contents($path, "<?php\ndefine( 'DB_NAME', 'wp' );\n\n/* That's all, stop editing! */\n\nrequire_once ABSPATH . 'wp-settings.php';\n");

        $supplyPath = function () use ($path) {
            return $path;
        };

        add_filter('fluent_auth/wp_config_path', $supplyPath);

        // No key readable in this process, which is exactly the real situation after a write.
        $this->keyValue = '';

        $response = TwoFaEncryptionController::writeConfig($this->request());

        $this->assertTrue($response['written']);
        $this->assertStringContainsString('wp-config.php', $response['message']);

        // The line is in the file...
        $this->assertStringContainsString('FLUENT_AUTH_SECURITY_KEY', file_get_contents($path));

        // ...and encryption is still off, because this process cannot see it.
        $this->assertFalse($response['encryption']['enabled']);
        $this->assertFalse(SecretKey::isEnabled());

        remove_filter('fluent_auth/wp_config_path', $supplyPath);

        @unlink($path);
        foreach (glob($dir . '/.*') ?: [] as $stray) {
            if (!is_dir($stray)) {
                @unlink($stray);
            }
        }
        @rmdir($dir);
    }

    /**
     * The line written must be the line the screen showed, or somebody who copied it into
     * their password manager has a value that opens nothing.
     *
     * @test
     */
    public function it_writes_the_same_value_it_offered_on_screen()
    {
        $dir = get_temp_dir() . 'fls-enc-ctrl-' . wp_generate_password(8, false);
        mkdir($dir);
        $path = $dir . '/wp-config.php';
        file_put_contents($path, "<?php\n\n/* That's all, stop editing! */\n");

        $supplyPath = function () use ($path) {
            return $path;
        };

        add_filter('fluent_auth/wp_config_path', $supplyPath);

        $this->keyValue = '';

        $offered = TwoFaEncryptionController::getStatus($this->request())['encryption']['proposed_line'];

        TwoFaEncryptionController::writeConfig($this->request());

        $this->assertStringContainsString(trim($offered), file_get_contents($path));

        remove_filter('fluent_auth/wp_config_path', $supplyPath);

        @unlink($path);
        foreach (glob($dir . '/.*') ?: [] as $stray) {
            if (!is_dir($stray)) {
                @unlink($stray);
            }
        }
        @rmdir($dir);
    }

    /**
     * A read-only wp-config.php is the ordinary case on managed hosting, so it comes back as
     * a result with a sentence to show - not as a failed request with a red notification
     * over a panel that is about to say what to do instead.
     *
     * @test
     */
    public function a_refused_write_is_reported_as_a_result_rather_than_an_error()
    {
        $blockIt = '__return_true';

        add_filter('fluent_auth/wp_config_write_blocked', $blockIt);

        $this->keyValue = '';

        $response = TwoFaEncryptionController::writeConfig($this->request());

        $this->assertFalse(is_wp_error($response));
        $this->assertFalse($response['written']);
        $this->assertStringContainsString('by hand', $response['message']);

        remove_filter('fluent_auth/wp_config_write_blocked', $blockIt);
    }

    /** @test */
    public function it_does_not_write_when_a_key_is_already_in_place()
    {
        $response = TwoFaEncryptionController::writeConfig($this->request());

        $this->assertFalse($response['written']);
        $this->assertStringContainsString('already in place', $response['message']);
    }

    /** @test */
    public function it_reports_where_wp_config_is_and_whether_it_could_be_written()
    {
        $status = TwoFaEncryptionController::getStatus($this->request())['encryption'];

        $this->assertArrayHasKey('config', $status);
        $this->assertArrayHasKey('found', $status['config']);
        $this->assertArrayHasKey('writable', $status['config']);
        $this->assertArrayHasKey('blocked', $status['config']);
    }
}
