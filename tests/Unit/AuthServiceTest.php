<?php

namespace FluentAuth\Tests\Unit;

use FluentAuth\App\Services\AuthService;

class AuthServiceTest extends BaseTestCase
{
    public function testDoUserAuthSuccessExistingUser()
    {
        $userId = $this->factory->user->create([
            'user_email' => 'existing@example.com',
            'user_login' => 'existinguser',
            'first_name' => 'Existing',
            'last_name' => 'User',
        ]);

        wp_set_current_user(0);

        $userData = [
            'email' => 'existing@example.com',
            'first_name' => 'Updated',
            'last_name' => 'Name'
        ];

        $result = AuthService::doUserAuth($userData);

        $this->assertNotInstanceOf(\WP_Error::class, $result);
    }

    public function testDoUserAuthSuccessNewUser()
    {
        wp_set_current_user(0);
        update_option('users_can_register', '1');
        update_option('default_role', 'subscriber');

        $userData = [
            'email' => 'brandnew@example.com',
            'first_name' => 'New',
            'last_name' => 'User'
        ];

        $result = AuthService::doUserAuth($userData);

        $this->assertNotInstanceOf(\WP_Error::class, $result);
    }

    public function testDoUserAuthInvalidEmail()
    {
        wp_set_current_user(0);

        $userData = [
            'email' => 'invalid-email',
            'first_name' => 'Test',
            'last_name' => 'User'
        ];

        $result = AuthService::doUserAuth($userData);

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertEquals('invalid_email', $result->get_error_code());
    }

    public function testDoUserAuthRegistrationDisabled()
    {
        wp_set_current_user(0);
        update_option('users_can_register', '');
        update_option('default_role', 'subscriber');

        $userData = [
            'email' => 'newuser_noreg@example.com',
            'first_name' => 'New',
            'last_name' => 'User'
        ];

        $result = AuthService::doUserAuth($userData);

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertEquals('signup_disabled', $result->get_error_code());
    }

    public function testDoUserAuthAlreadyLoggedIn()
    {
        $userId = $this->factory->user->create();
        wp_set_current_user($userId);

        $userData = [
            'email' => 'test@example.com',
            'first_name' => 'Test',
            'last_name' => 'User'
        ];

        $result = AuthService::doUserAuth($userData);

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertEquals('already_logged_in', $result->get_error_code());
    }

    public function testMakeLogin()
    {
        $userId = $this->factory->user->create([
            'user_email' => 'logintest@example.com',
            'user_login' => 'loginuser',
        ]);

        $user = get_user_by('ID', $userId);
        $result = AuthService::makeLogin($user);

        $this->assertNotInstanceOf(\WP_Error::class, $result);
    }

    public function testSetStateToken()
    {
        @$token = AuthService::setStateToken();
        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testGetStateToken()
    {
        $_COOKIE['fs_auth_state'] = 'test_state_token';

        $token = AuthService::getStateToken();
        $this->assertEquals('test_state_token', $token);

        unset($_COOKIE['fs_auth_state']);
    }

    public function testRegisterNewUserSuccess()
    {
        $result = AuthService::registerNewUser('reguser1', 'reguser1@example.com', 'password123');

        $this->assertIsInt($result);
        $this->assertGreaterThan(0, $result);
    }

    public function testRegisterNewUserWithExtraData()
    {
        $extraData = [
            'first_name' => 'Test',
            'last_name' => 'User',
            '__validated' => true,
        ];

        $result = AuthService::registerNewUser('reguser2', 'reguser2@example.com', 'password123', $extraData);

        $this->assertIsInt($result);
        $this->assertGreaterThan(0, $result);
    }

    public function testCheckUserRegDataErrors()
    {
        $errors = AuthService::checkUserRegDataErrors('validuser', 'valid@example.com');
        $this->assertInstanceOf(\WP_Error::class, $errors);
        $this->assertFalse($errors->has_errors());

        $errors = AuthService::checkUserRegDataErrors('', 'valid@example.com');
        $this->assertInstanceOf(\WP_Error::class, $errors);
        $this->assertTrue($errors->has_errors());

        $errors = AuthService::checkUserRegDataErrors('validuser2', 'invalid-email');
        $this->assertInstanceOf(\WP_Error::class, $errors);
        $this->assertTrue($errors->has_errors());
    }

    public function testCheckUserRegDataErrorsWithExtraArgs()
    {
        $extraArgs = ['first_name' => 'Test'];
        $errors = AuthService::checkUserRegDataErrors('extrauser', 'extra@example.com', $extraArgs);

        $this->assertInstanceOf(\WP_Error::class, $errors);
        $this->assertFalse($errors->has_errors());
    }

    public function testVerifyTokenHashSuccess()
    {
        global $wpdb;
        $token = 'test_token_123';
        $hash = wp_hash_password($token);
        $loginHash = wp_generate_password(32, false);

        $wpdb->insert($wpdb->prefix . 'fls_login_hashes', [
            'login_hash' => $loginHash,
            'status' => 'issued',
            'use_type' => 'signup_verification',
            'used_count' => 0,
            'two_fa_code_hash' => $hash,
            'valid_till' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'created_at' => current_time('mysql'),
        ]);

        $result = AuthService::verifyTokenHash($loginHash, $token);

        $this->assertTrue($result);
    }

    public function testVerifyTokenHashFailure()
    {
        global $wpdb;
        $hash = wp_hash_password('wrong_token');
        $loginHash = wp_generate_password(32, false);

        $wpdb->insert($wpdb->prefix . 'fls_login_hashes', [
            'login_hash' => $loginHash,
            'status' => 'issued',
            'use_type' => 'signup_verification',
            'used_count' => 0,
            'two_fa_code_hash' => $hash,
            'valid_till' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'created_at' => current_time('mysql'),
        ]);

        $result = AuthService::verifyTokenHash($loginHash, 'test_token');

        $this->assertInstanceOf(\WP_Error::class, $result);
    }

    public function testVerifyTokenHashInvalidHash()
    {
        $result = AuthService::verifyTokenHash('nonexistent_hash', 'test_token');

        $this->assertInstanceOf(\WP_Error::class, $result);
    }

    public function testVerifyTokenHashSuccessWithEmail()
    {
        global $wpdb;
        $token = '534212';
        $email = 'verified@example.com';
        $hash = wp_hash_password($token . '|' . strtolower(trim($email)));
        $loginHash = wp_generate_password(32, false);

        $wpdb->insert($wpdb->prefix . 'fls_login_hashes', [
            'login_hash' => $loginHash,
            'status' => 'issued',
            'use_type' => 'signup_verification',
            'used_count' => 0,
            'two_fa_code_hash' => $hash,
            'valid_till' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'created_at' => current_time('mysql'),
        ]);

        $result = AuthService::verifyTokenHash($loginHash, $token, $email);

        $this->assertTrue($result);
    }

    public function testVerifyTokenHashRejectsMismatchedEmail()
    {
        global $wpdb;
        $token = '534212';
        $issuedFor = 'attacker@evil.com';
        $hash = wp_hash_password($token . '|' . strtolower(trim($issuedFor)));
        $loginHash = wp_generate_password(32, false);

        $wpdb->insert($wpdb->prefix . 'fls_login_hashes', [
            'login_hash' => $loginHash,
            'status' => 'issued',
            'use_type' => 'signup_verification',
            'used_count' => 0,
            'two_fa_code_hash' => $hash,
            'valid_till' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'created_at' => current_time('mysql'),
        ]);

        $result = AuthService::verifyTokenHash($loginHash, $token, 'victim@example.com');

        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertEquals('invalid_verification_code', $result->get_error_code());
    }

    public function testVerifyTokenHashEmailIsCaseAndWhitespaceInsensitive()
    {
        global $wpdb;
        $token = '534212';
        $hash = wp_hash_password($token . '|' . strtolower(trim('User@Example.com')));
        $loginHash = wp_generate_password(32, false);

        $wpdb->insert($wpdb->prefix . 'fls_login_hashes', [
            'login_hash' => $loginHash,
            'status' => 'issued',
            'use_type' => 'signup_verification',
            'used_count' => 0,
            'two_fa_code_hash' => $hash,
            'valid_till' => date('Y-m-d H:i:s', strtotime('+1 hour')),
            'created_at' => current_time('mysql'),
        ]);

        $result = AuthService::verifyTokenHash($loginHash, $token, '  user@example.com  ');

        $this->assertTrue($result);
    }

    public function testDoUserAuthWithProvider()
    {
        wp_set_current_user(0);
        update_option('users_can_register', '1');
        update_option('default_role', 'subscriber');

        $userData = [
            'email' => 'provideruser@example.com',
            'first_name' => 'Provider',
            'last_name' => 'User'
        ];

        $result = AuthService::doUserAuth($userData, 'google');

        $this->assertNotInstanceOf(\WP_Error::class, $result);
    }

    public function testMakeLoginWithProvider()
    {
        $userId = $this->factory->user->create([
            'user_email' => 'provlogin@example.com',
            'user_login' => 'provloginuser',
        ]);

        $user = get_user_by('ID', $userId);
        $result = AuthService::makeLogin($user, 'google');

        $this->assertNotInstanceOf(\WP_Error::class, $result);
    }
}
